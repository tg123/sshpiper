// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package ssh in sshpiper is compatible with golang.org/x/crypto/ssh.
All func and datatype left unchanged. You can use it like golang.org/x/crypto/ssh.

Also, sshpiper provide additional APIs that allows build a piped ssh connection.

SSH is a transport security protocol, an authentication protocol and a
family of application protocols. The most typical application level
protocol is a remote shell and this is specifically implemented.  However,
the multiplexed nature of SSH is exposed to users that wish to support
others.

References:
  [PROTOCOL.certkeys]: http://www.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys
  [SSH-PARAMETERS]:    http://www.iana.org/assignments/ssh-parameters/ssh-parameters.xml#ssh-parameters-1
*/
package ssh
