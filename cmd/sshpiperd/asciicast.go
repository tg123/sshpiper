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
	msgChannelRequest     = 98
	msgChannelOpenConfirm = 91
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
	err := binary.Read(buf, binary.BigEndian, &l)
	if err != nil {
		return ""
	}
	s := make([]byte, l)
	_, err = buf.Read(s)
	if err != nil {
		return ""
	}
	return string(s)
}

type asciicastLogger struct {
	starttime    time.Time
	envs         map[string]string
	initWidth    uint32
	initHeight   uint32
	channels     map[uint32]*os.File
	channelIDMap map[uint32]uint32
	recorddir    string
	prefix       string // prefix for the output file
}

func newAsciicastLogger(recorddir string, prefix string) *asciicastLogger {
	return &asciicastLogger{
		envs:         make(map[string]string),
		recorddir:    recorddir,
		channels:     make(map[uint32]*os.File),
		channelIDMap: make(map[uint32]uint32),
		prefix:       prefix,
	}
}

func (l *asciicastLogger) uphook(msg []byte) ([]byte, error) {
	if msg[0] == msgChannelData {
		clientChannelID := binary.BigEndian.Uint32(msg[1:5])

		f, ok := l.channels[clientChannelID]
		if ok {
			buf := msg[9:]
			t := time.Since(l.starttime).Seconds()

			_, err := fmt.Fprintf(f, "[%v,\"o\",\"%s\"]\n", t, jsonEscape(string(buf)))

			if err != nil {
				return msg, err
			}
		}
	} else if msg[0] == msgChannelOpenConfirm {
		clientChannelID := binary.BigEndian.Uint32(msg[1:5])
		serverChannelID := binary.BigEndian.Uint32(msg[5:9])
		l.channelIDMap[serverChannelID] = clientChannelID
	}
	return msg, nil
}

func (l *asciicastLogger) downhook(msg []byte) ([]byte, error) {
	if msg[0] == msgChannelRequest {
		t := time.Since(l.starttime).Seconds()
		serverChannelID := binary.BigEndian.Uint32(msg[1:5])
		clientChannelID := l.channelIDMap[serverChannelID]
		buf := bytes.NewReader(msg[5:])
		reqType := readString(buf)

		switch reqType {
		case "pty-req":
			_, _ = buf.ReadByte()
			term := readString(buf)
			_ = binary.Read(buf, binary.BigEndian, &l.initWidth)
			_ = binary.Read(buf, binary.BigEndian, &l.initHeight)
			l.envs["TERM"] = term
		case "env":
			_, _ = buf.ReadByte()
			varName := readString(buf)
			varValue := readString(buf)
			l.envs[varName] = varValue
		case "window-change":
			f, ok := l.channels[clientChannelID]
			if !ok {
				_, _ = buf.ReadByte()
				var width, height uint32
				_ = binary.Read(buf, binary.BigEndian, &width)
				_ = binary.Read(buf, binary.BigEndian, &height)

				_, err := fmt.Fprintf(f, "[%v,\"r\", \"%vx%v\"]\n", t, width, height)
				if err != nil {
					return msg, err
				}
			}
		case "shell", "exec":
			jsonEnvs, err := json.Marshal(l.envs)

			if err != nil {
				return msg, err
			}

			f, err := os.OpenFile(
				path.Join(l.recorddir, fmt.Sprintf("%s%s-channel-%d.cast", l.prefix, reqType, clientChannelID)),
				os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
				0600,
			)

			if err != nil {
				return msg, err
			}

			l.channels[clientChannelID] = f

			l.starttime = time.Now()

			_, err = fmt.Fprintf(
				f,
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
	for _, f := range l.channels {
		_ = f.Close()
	}
	return nil
}
