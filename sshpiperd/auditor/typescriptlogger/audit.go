package typescriptlogger

import (
	"fmt"
	"os"
	"path"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	msgChannelData = 94
)

type filePtyLogger struct {
	typescript *os.File
	timing     *os.File

	oldtime time.Time
}

func newFilePtyLogger(outputdir string) (*filePtyLogger, error) {

	now := time.Now()

	filename := fmt.Sprintf("%d", now.Unix())

	typescript, err := os.OpenFile(path.Join(outputdir, fmt.Sprintf("%v.typescript", filename)), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	if err != nil {
		return nil, err
	}

	_, err = typescript.Write([]byte(fmt.Sprintf("Script started on %v\n", now.Format(time.ANSIC))))

	if err != nil {
		return nil, err
	}

	timing, err := os.OpenFile(path.Join(outputdir, fmt.Sprintf("%v.timing", filename)), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	if err != nil {
		return nil, err
	}

	return &filePtyLogger{
		typescript: typescript,
		timing:     timing,
		oldtime:    time.Now(),
	}, nil
}

func (l *filePtyLogger) loggingTty(conn ssh.ConnMetadata, msg []byte) ([]byte, error) {

	if msg[0] == msgChannelData {

		buf := msg[9:]

		now := time.Now()

		delta := now.Sub(l.oldtime)

		// see term-utils/script.c
		fmt.Fprintf(l.timing, "%v.%06v %v\n", int64(delta/time.Second), int64(delta/time.Microsecond), len(buf))

		l.oldtime = now

		_, err := l.typescript.Write(buf)

		if err != nil {
			return msg, err
		}

	}

	return msg, nil
}

func (l *filePtyLogger) Close() (err error) {
	// if _, err = ; err != nil {
	// return err
	// }
	_, _ = l.typescript.Write([]byte(fmt.Sprintf("Script done on %v\n", time.Now().Format(time.ANSIC))))

	l.typescript.Close()
	l.timing.Close()

	return nil // TODO
}
