package pome

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

func (p *pome) load(ctx context.Context, id string) (*pipe, error) {
	req, err := http.NewRequest("GET", p.Config.CheckBaseURL+id, nil)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("bad http state code %v", resp.StatusCode)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	pipe := pipe{}

	if err := json.Unmarshal(body, &pipe); err != nil {
		return nil, err
	}

	return &pipe, nil
}

func (p *pome) loadWithRetry(ctx context.Context, id string) <-chan *pipe {
	c := make(chan *pipe)
	go func() {
		for {
			select {
			case <-ctx.Done():
				c <- nil
				return
			default:
				timeout, cancel := context.WithTimeout(context.Background(), time.Millisecond*5000)
				defer cancel()
				pipe, err := p.load(timeout, id)

				if err == nil {
					c <- pipe
					return
				}

				time.Sleep(time.Millisecond * 5000)
			}
		}
	}()
	return c
}

func (p *pome) challenge(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (ssh.AdditionalChallengeContext, error) {

	uid, err := uuid.NewRandom()

	if err != nil {
		return nil, err
	}

	id := uid.String()
	url := p.Config.LoginBaseURL + id

	say := func(msg string) error {
		_, err = client(conn.User(), msg, nil, nil)
		return err
	}

	if err := say(fmt.Sprintf("Open %v in browser to login (timeout %v senconds)", url, p.Config.Timeout)); err != nil {
		return nil, err
	}

	d := time.Now().Add(time.Duration(p.Config.Timeout) * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()
	c := p.loadWithRetry(ctx, id)

	pipe := <-c

	if pipe == nil {
		_ = say("Login timeout")
		return nil, fmt.Errorf("timeout")
	}

	_ = say(fmt.Sprintf("Connecting to %v@%v", pipe.Username, pipe.Address))

	pipe.say = say
	return pipe, nil
}
