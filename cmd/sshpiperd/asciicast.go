package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"time"
)

const (
	msgChannelRequest = 98
)

func jsonEscape(i string) string {
	b, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}
	s := string(b)
	return s[1 : len(s)-1]
}

func readString(buf *bytes.Reader) string {
	var l uint32
	binary.Read(buf, binary.BigEndian, &l)
	s := make([]byte, l)
	buf.Read(s)
	return string(s)
}

type asciicastLogger struct {
	cast       *os.File
	starttime  time.Time
	envs       map[string]string
	initWidth  uint32
	initHeight uint32
}

func newAsciicastLogger(logdir string) (*asciicastLogger, error) {
	f, err := os.OpenFile(path.Join(logdir, "shell.cast"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	if err != nil {
		return nil, err
	}

	return &asciicastLogger{
		cast:      f,
		starttime: time.Now(),
		envs:      make(map[string]string),
	}, nil
}

func (l *asciicastLogger) uphook(msg []byte) ([]byte, error) {
	if msg[0] == msgChannelData {
		buf := msg[9:]
		t := time.Since(l.starttime).Seconds()

		_, err := fmt.Fprintf(l.cast, "[%v,\"o\",\"%s\"]\n", t, jsonEscape(string(buf)))

		if err != nil {
			return msg, err
		}

	}
	return msg, nil
}

func (l *asciicastLogger) downhook(msg []byte) ([]byte, error) {
	if msg[0] == msgChannelRequest {
		t := time.Since(l.starttime).Seconds()
		buf := bytes.NewReader(msg[5:])
		reqType := readString(buf)

		switch reqType {
		case "pty-req":
			buf.ReadByte()
			term := readString(buf)
			binary.Read(buf, binary.BigEndian, &l.initWidth)
			binary.Read(buf, binary.BigEndian, &l.initHeight)
			l.envs["TERM"] = term
		case "env":
			buf.ReadByte()
			varName := readString(buf)
			varValue := readString(buf)
			l.envs[varName] = varValue
		case "window-change":
			buf.ReadByte()
			var width, height uint32
			binary.Read(buf, binary.BigEndian, &width)
			binary.Read(buf, binary.BigEndian, &height)
			_, err := fmt.Fprintf(l.cast, "[%v,\"r\", \"%vx%v\"]\n", t, width, height)
			if err != nil {
				return msg, err
			}
		case "shell", "exec":
			jsonEnvs, err := json.Marshal(l.envs)

			if err != nil {
				return msg, err
			}

			_, err = fmt.Fprintf(
				l.cast,
				"{\"version\": 2, \"width\": %d, \"height\": %d, \"timestamp\": %d, \"env\": %v}\n",
				l.initWidth,
				l.initHeight,
				l.starttime.Unix(),
				string(jsonEnvs),
			)

			if err != nil {
				return msg, err
			}
		}
	}
	return msg, nil
}

func (l *asciicastLogger) Close() (err error) {
	l.cast.Close()
	return nil
}
