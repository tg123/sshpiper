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

// Close closes the cmdconn and releases any associated resources.
// It first closes the underlying connection and then kills the process if it is running.
// If an error occurs during the closing of the connection, that error is returned.
// If the process is running and cannot be killed, an error is returned.
func (c *cmdconn) Close() error {
	err := c.conn.Close()

	if c.cmd.Process != nil {
		return c.cmd.Process.Kill()
	}

	return err
}

// DialCmd is a function that establishes a connection to a command's standard input, output, and error streams.
// It takes a *exec.Cmd as input and returns a net.Conn, io.ReadCloser, and error.
// The net.Conn represents the connection to the command's standard input and output streams.
// The io.ReadCloser represents the command's standard error stream.
// The error represents any error that occurred during the connection establishment.
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
