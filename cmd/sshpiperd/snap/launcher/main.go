package main

import (
	"embed"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
)

//go:embed all:*.txt
var configentry embed.FS

func main() {
	bindir := os.Getenv("SNAP")
	datadir := os.Getenv("SNAP_DATA")

	flags := map[string][][]string{}
	configfile := path.Join(datadir, "flags.json")

	if len(os.Args) > 1 && os.Args[1] == "generate" {
		flags = loadFromSnapctl()
		cache, _ := json.Marshal(flags)
		if err := os.WriteFile(configfile, cache, 0600); err != nil {
			log.Fatal(err)
		}

		return
	}

	cache, _ := os.ReadFile(configfile)
	_ = json.Unmarshal(cache, &flags)

	cmd := exec.Command(path.Join(bindir, "sshpiperd"))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	for _, flag := range flags["sshpiperd"] {
		cmd.Args = append(cmd.Args, "--"+flag[0], flag[1])
	}

	for _, plugin := range flags["sshpiperd.plugins"][0] {
		cmd.Args = append(cmd.Args, path.Join(bindir, plugin))
		for _, flag := range flags[plugin] {
			cmd.Args = append(cmd.Args, "--"+flag[0], flag[1])
		}
		cmd.Args = append(cmd.Args, "--")
	}

	log.Println("starting sshpiperd with args:", cmd)
	_ = cmd.Run()
}

func loadFromSnapctl() map[string][][]string {
	commondir := os.Getenv("SNAP_COMMON")

	flags := map[string][][]string{}

	data, err := configentry.ReadFile("configentry.txt")
	if err != nil {
		log.Fatal(err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, " ")
		if len(parts) == 0 {
			continue
		}

		opt := parts[0]
		v, err := get(opt)
		if err != nil {
			log.Printf("error getting %v: %v", line, err)
		}

		if v == "" {
			continue
		}

		parts = strings.Split(opt, ".")
		ns := parts[0]
		flag := parts[1]

		flags[ns] = append(flags[ns], []string{flag, v})
	}

	// known defaults
	{
		v, _ := get("sshpiperd.plugins")
		if v == "" {
			v = "workingdir"
		}

		var plugins []string
		for _, str := range strings.Split(v, " ") {
			str = strings.TrimSpace(str)
			if str != "" {
				plugins = append(plugins, str)
			}
		}

		flags["sshpiperd.plugins"] = [][]string{plugins}
	}

	// {
	// 	v, _ := get("sshpiperd.typescript-log-dir")
	// 	if v == "" {
	// 		v = "screenrecord"
	// 		dir := path.Join(commondir, v)
	// 		_ = os.MkdirAll(dir, 0700)
	// 		flags["sshpiperd"] = append(flags["sshpiperd"], []string{"typescript-log-dir", dir})
	// 	}
	// }

	{
		v, _ := get("sshpiperd.server-key-generate-mode")
		if v == "" {
			v = "notexist"
			flags["sshpiperd"] = append(flags["sshpiperd"], []string{"server-key-generate-mode", v})
		}
	}

	{
		v, _ := get("sshpiperd.server-key")
		if v == "" {
			v = "ssh_host_ed25519_key"
			file := path.Join(commondir, v)
			flags["sshpiperd"] = append(flags["sshpiperd"], []string{"server-key", file})
		}
	}

	{
		v, _ := get("workingdir.root")
		if v == "" {
			v = "workingdir"

			dir := path.Join(commondir, v)
			_ = os.MkdirAll(dir, 0700)
			flags["workingdir"] = append(flags["workingdir"], []string{"root", dir})
		}
	}

	return flags
}

func get(key string) (string, error) {
	cmd := exec.Command("snapctl", "get", key)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	value := string(output)
	return strings.TrimSpace(value), nil
}
