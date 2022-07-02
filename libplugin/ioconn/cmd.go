package ioconn

import (
	"io"
	"net"
	"os/exec"
)

type cmdconn struct {
	conn
	cmd *exec.Cmd
}

func (c *cmdconn) Close() error {
	err := c.conn.Close()

	if c.cmd.Process != nil {
		return c.cmd.Process.Kill()
	}

	return err
}

func DialCmd(cmd *exec.Cmd) (net.Conn, io.ReadCloser, error) {
	in, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}

	out, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	return &cmdconn{
		conn: *dial(in, out),
		cmd:  cmd,
	}, stderr, nil
}
