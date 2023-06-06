package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"crypto/tls"
	"fmt"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/fatih/color"
)

type plugin struct {
	URL        string
	Insecure bool
}

func newRestChallengePlugin() *plugin{
	return &plugin{

	}
}

func (p *plugin) challenge(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error){
	for {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: p.Insecure}
		resp, err := http.Get(p.URL + fmt.Sprintf("/%s", url.QueryEscape(conn.User())))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			var result map[string]interface{}
			json.Unmarshal([]byte(body), &result)

			if result["challenge"] == false {
				return &libplugin.Upstream{
					Auth: libplugin.CreateNextPluginAuth(map[string]string{
						"challenge": "false",
					}),
				}, nil
			}else{
				_, _ = client("", color.RedString("warning"), "", false)

				response, err := client("", "", fmt.Sprintf("%v\n", result["message"]), true)

				if err != nil {
					return nil, err
				}
		
				values := map[string]string{"user":conn.User(),"remoteAddr":conn.RemoteAddr(), "uuid":conn.UniqueID(),"response":response}
				post, err := json.Marshal(values)
				if err != nil {
					return nil, err
				}
				resp, err := http.Post(p.URL + fmt.Sprintf("/%s", url.QueryEscape(conn.User())), "application/json", bytes.NewBuffer(post) )
				if err != nil {
					return nil, err
				}
				defer resp.Body.Close()
				if resp.StatusCode == 200 {
					body, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						return nil, err
					}
					var result map[string]interface{}
					json.Unmarshal([]byte(body), &result)

					if result["auth"] == true {
						return &libplugin.Upstream{
							Auth: libplugin.CreateNextPluginAuth(map[string]string{
								"response": response,
							}),
						}, nil
					}else{
						return nil, err
					}
				} else {
					return nil, err
				}
			}			
	
		} else {
			return nil, err
		}
	}
}