package sharethis

import "golang.org/x/crypto/ssh"

type NewChannel struct {
	ssh.NewChannel
	DoZip bool
}
