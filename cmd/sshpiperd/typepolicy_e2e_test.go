package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The Go SSH client serializes want-reply global requests. Set the denied
// request's WantReply bit in the test hook to emulate a pipelined client
// without a second SSH implementation. All transport, piping, policy hooks,
// unrelated channel traffic, and disconnect handling remain real.
func TestTypePolicyFilterPiperUnansweredRequest(t *testing.T) {
	for _, checkTraffic := range []bool{false, true} {
		name := "disconnect"
		if checkTraffic {
			name = "channel traffic then disconnect"
		}
		t.Run(name, func(t *testing.T) {
			hostKey := genHostKey(t)
			upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { upstreamLn.Close() })
			upstreamRequests := make(chan *ssh.Request, 4)
			upstreamDone := make(chan struct{})
			go func() {
				defer close(upstreamDone)
				c, err := upstreamLn.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				t.Cleanup(func() { c.Close() })
				cfg := &ssh.ServerConfig{NoClientAuth: true}
				cfg.AddHostKey(hostKey)
				_, channels, requests, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					t.Errorf("upstream handshake: %v", err)
					return
				}
				requestsDone := make(chan struct{})
				go func() {
					defer close(requestsDone)
					for request := range requests {
						// Intentionally leave every global request unanswered.
						upstreamRequests <- request
					}
				}()
				for channel := range channels {
					ch, requests, err := channel.Accept()
					if err != nil {
						t.Errorf("upstream channel: %v", err)
						continue
					}
					go ssh.DiscardRequests(requests)
					go func() {
						defer ch.Close()
						_, _ = io.Copy(ch, ch)
					}()
				}
				<-requestsDone
			}()

			piperLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { piperLn.Close() })
			cfg := &ssh.PiperConfig{
				NoClientAuthCallback: func(ssh.ConnMetadata, ssh.ChallengeContext) (*ssh.Upstream, error) {
					c, err := net.DialTimeout("tcp", upstreamLn.Addr().String(), 5*time.Second)
					if err != nil {
						return nil, err
					}
					return &ssh.Upstream{
						Conn: c,
						ClientConfig: ssh.ClientConfig{
							User:            "u",
							Auth:            []ssh.AuthMethod{ssh.NoneAuth()},
							HostKeyCallback: ssh.InsecureIgnoreHostKey(),
						},
					}, nil
				},
			}
			cfg.AddHostKey(hostKey)
			policy := disableRemoteForwardPolicy(t)
			ready := make(chan *typePolicyFilter, 1)
			blockedSeen := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := piperLn.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				t.Cleanup(func() { c.Close() })
				p, err := ssh.NewSSHPiperConn(c, cfg)
				if err != nil {
					t.Errorf("piper handshake: %v", err)
					return
				}
				defer p.Close()
				t.Cleanup(p.Close)
				filter := newTypePolicyFilter(p.WriteDownstreamPacket, nil, policy)
				ready <- filter
				up, down := &hookChain{}, &hookChain{}
				up.append(filter.up)
				down.append(func(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
					if len(packet) > 0 && packet[0] == msgGlobalRequest {
						var request globalRequest
						if err := ssh.Unmarshal(packet, &request); err == nil && request.Type == "tcpip-forward" {
							request.WantReply = true
							packet = ssh.Marshal(request)
							close(blockedSeen)
						}
					}
					return ssh.PipePacketHookTransform, packet, nil
				})
				down.append(filter.down)
				_ = p.WaitWithHook(up.hook(), down.hook())
				filter.close()
			}()

			raw, err := net.DialTimeout("tcp", piperLn.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { raw.Close() })
			if err := raw.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
				t.Fatal(err)
			}
			conn, channels, requests, err := ssh.NewClientConn(raw, piperLn.Addr().String(), &ssh.ClientConfig{
				User:            "alice",
				Auth:            []ssh.AuthMethod{ssh.NoneAuth()},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			})
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			client := ssh.NewClient(conn, channels, requests)
			t.Cleanup(func() { client.Close() })
			var filter *typePolicyFilter
			select {
			case filter = <-ready:
			case <-time.After(5 * time.Second):
				t.Fatal("piper did not become ready")
			}

			requestDone := make(chan error, 1)
			go func() {
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				requestDone <- err
			}()
			select {
			case request := <-upstreamRequests:
				if request.Type != "keepalive@openssh.com" || !request.WantReply {
					t.Fatalf("unexpected upstream request: %v", request)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("upstream did not receive the allowed request")
			}
			if _, _, err := client.SendRequest("tcpip-forward", false, nil); err != nil {
				t.Fatal(err)
			}
			waitDone(t, blockedSeen)

			if checkTraffic {
				trafficDone := make(chan error, 1)
				go func() {
					ch, requests, err := client.OpenChannel("session", nil)
					if err != nil {
						trafficDone <- err
						return
					}
					defer ch.Close()
					go ssh.DiscardRequests(requests)
					payload := []byte("traffic after blocked forwarding")
					if _, err := ch.Write(payload); err != nil {
						trafficDone <- err
						return
					}
					got := make([]byte, len(payload))
					_, err = io.ReadFull(ch, got)
					if err == nil && !bytes.Equal(got, payload) {
						err = io.ErrUnexpectedEOF
					}
					trafficDone <- err
				}()
				select {
				case err := <-trafficDone:
					if err != nil {
						t.Fatalf("channel traffic: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("unanswered global request stalled later channel traffic")
				}
			}

			select {
			case err := <-requestDone:
				t.Fatalf("unanswered request completed before disconnect: %v", err)
			default:
			}
			select {
			case request := <-upstreamRequests:
				t.Fatalf("blocked request reached upstream: %v", request)
			default:
			}
			client.Close()
			// The upstream stays open and idle until PiperConn detects the
			// client's EOF; test cleanup must not be what releases the pipe.
			waitDone(t, done)
			waitDone(t, upstreamDone)
			assertTypePolicyFilterClosed(t, filter)
			select {
			case err := <-requestDone:
				if err == nil {
					t.Fatal("unanswered request succeeded after disconnect")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("outstanding client request did not exit after disconnect")
			}
		})
	}
}
