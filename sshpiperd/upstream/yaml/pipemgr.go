package yaml

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"gopkg.in/yaml.v3"
)

// Return All pipes inside upstream
func (p *plugin) ListPipe() ([]upstream.Pipe, error) {

	config, err := p.loadConfig()

	if err != nil {
		return nil, err
	}

	out, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}

	fmt.Println(string(out))

	var pipes []upstream.Pipe

	for _, pipe := range config.Pipes {
		host, port, err := upstream.SplitHostPortForSSH(pipe.UpstreamHost)

		if err != nil {
			return nil, err
		}

		mappeduser := pipe.Authmap.MappedUsername

		if mappeduser == "" {
			mappeduser = pipe.Username
		}

		pipes = append(pipes, upstream.Pipe{
			Host:             host,
			Port:             port,
			UpstreamUsername: mappeduser,
			Username:         pipe.Username,
		})
	}

	return pipes, nil
}

func findnode(root *yaml.Node, test func(*yaml.Node) bool) *yaml.Node {
	var q []*yaml.Node

	q = append(q, root)

	for len(q) > 0 {
		e := q[0]
		q = q[1:]

		if test(e) {
			return e
		}

		for _, n := range e.Content {
			q = append(q, n)
		}
	}

	return nil
}

func findByMapKey(m *yaml.Node, k string) (*yaml.Node, int) {
	for i := 1; i < len(m.Content); i += 2 {
		if m.Content[i-1].Value == k {
			return m.Content[i], i
		}
	}

	return nil, -1
}

func toYamlNode(s interface{}) (*yaml.Node, error) {
	t := yaml.Node{}

	out, err := yaml.Marshal(s)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(out, &t)
	if err != nil {
		return nil, err
	}

	return t.Content[0], nil
}

func (p *plugin) loadConfigRaw() ([]byte, *yaml.Node, error) {
	var config yaml.Node

	configbyte, err := ioutil.ReadFile(p.Config.File)
	if err != nil {
		return nil, nil, err
	}

	err = yaml.Unmarshal(configbyte, &config)
	if err != nil {
		return nil, nil, err
	}

	return configbyte, &config, nil
}

func (p *plugin) writeConfig(config []byte) error {
	return ioutil.WriteFile(p.Config.File, config, 0600)
}

func toPipeConfig(opt upstream.CreatePipeOption) pipeConfig {
	p := pipeConfig{
		Username:     opt.Username,
		UpstreamHost: fmt.Sprintf("%v:%v", opt.Host, opt.Port),
	}

	if len(opt.UpstreamUsername) > 0 {
		p.Authmap.MappedUsername = opt.UpstreamUsername
	}

	return p
}

// Create a pipe inside upstream
func (p *plugin) CreatePipe(opt upstream.CreatePipeOption) error {
	configbyte, config, err := p.loadConfigRaw()

	if err != nil {
		return err
	}

	if len(config.Content) == 0 {
		var buf bytes.Buffer
		buf.Write(configbyte)
		fmt.Fprintln(&buf)

		out, err := yaml.Marshal(piperConfig{
			Version: 1,
			Pipes:   []pipeConfig{toPipeConfig(opt)},
		})

		if err != nil {
			return err
		}

		buf.Write(out)

		return p.writeConfig(buf.Bytes())
	}

	pipes, idx := findByMapKey(config.Content[0], "pipes")

	if idx > 0 && pipes.Tag == "!!null" {
		// replace null
		t, err := toYamlNode([]pipeConfig{toPipeConfig(opt)})
		if err != nil {
			return err
		}

		config.Content[0].Content[idx] = t

		out, err := yaml.Marshal(config)
		if err != nil {
			return err
		}

		return p.writeConfig(out)
	}

	if pipes.Kind != yaml.SequenceNode {
		return fmt.Errorf("pipes should be !!seq")
	}

	for _, pnode := range pipes.Content {
		pipe, _ := findByMapKey(pnode, "username")

		if pipe != nil && pipe.Value == opt.Username {
			return fmt.Errorf("username [%v] already exists", opt.Username)
		}
	}

	// append

	{
		t, err := toYamlNode(toPipeConfig(opt))
		if err != nil {
			return err
		}

		pipes.Content = append(pipes.Content, t)

		out, err := yaml.Marshal(config)
		if err != nil {
			return err
		}

		return p.writeConfig(out)
	}
}

// Remove a pipe from upstream
func (p *plugin) RemovePipe(name string) error {
	_, config, err := p.loadConfigRaw()

	if err != nil {
		return err
	}

	if len(config.Content) == 0 {
		return nil
	}

	pipes, idx := findByMapKey(config.Content[0], "pipes")

	if idx > 0 && pipes.Tag == "!!null" {
		return nil
	}

	if pipes.Kind != yaml.SequenceNode {
		return fmt.Errorf("pipes should be !!seq")
	}

	for i, pnode := range pipes.Content {
		pipe, _ := findByMapKey(pnode, "username")

		if pipe != nil && pipe.Value == name {
			rest := pipes.Content[i+1:]
			pipes.Content = append(pipes.Content[:i], rest...)

			out, err := yaml.Marshal(config)
			if err != nil {
				return err
			}

			return p.writeConfig(out)
		}
	}

	return nil
}
