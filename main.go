package main // import "github.com/otremblay/sharethis"

import (
	"crypto/sha256"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type FileReq struct {
	Path string
}

type chanpair struct {
	sshchan *ssh.Channel
	sigchan chan struct{}
}

func main() {
	bg := flag.Bool("bg", false, "sends the process in the background")
	server := flag.Bool("server", false, "makes the process an http server")
	flag.Parse()
	if *server {
		runServer("0.0.0.0", "2022", "id_rsa")
	}
	if len(flag.Args()) < 1 {
		log.Fatalln("Need filename")
	}
	var path string
	if fs, err := os.Stat(flag.Arg(0)); err != nil {
		log.Fatalln("Can't read file")
	} else {
		p, err := filepath.Abs(fs.Name())
		if err != nil {
			log.Fatalln("Can't read file")
		}
		path = p
	}

	if *bg {
		_, err := syscall.ForkExec(os.Args[0], append([]string{os.Args[0]}, flag.Args()...), &syscall.ProcAttr{Files: []uintptr{0, 1, 2}})
		if err != nil {
			log.Fatalln(err)
		}
		os.Exit(0)
	}
	keypath := fmt.Sprintf("%s/.ssh/st_rsa", os.Getenv("HOME"))
	auth, err := PublicKeyFile(keypath)
	if err != nil {
		fmt.Println(err)
		auth = SSHAgent()
	}
	sshConfig := &ssh.ClientConfig{
		User: "otremblay",
		Auth: []ssh.AuthMethod{
			auth,
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	connection, err := ssh.Dial("tcp", "127.0.0.1:2022", sshConfig)
	if err != nil {
		log.Fatalln("Failed to dial: %s", err)
	}

	ch, reqch, err := connection.OpenChannel("Nope", nil)
	go ssh.DiscardRequests(reqch)
	if err != nil {
		log.Fatalln(err)
	}
	enc := gob.NewEncoder(ch)
	path = flag.Arg(0)
	var username string
	userobj, err := user.Current()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not get user with user.Current()")
		username = "unknown"
	} else {
		username = userobj.Username
	}
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not get hostname with os.Hostname()")
		hostname = "unknown"
	}
	fullpath := fmt.Sprintf("%s@%s:%s", username, hostname, path)
	hashedpath := fmt.Sprintf("%x", sha256.Sum256([]byte(fullpath)))
	// In the words of weezer, I've got my hashed path.
	fmt.Println(fmt.Sprintf("http://127.0.0.1:8888/%s", hashedpath))
	err = enc.Encode(&FileReq{hashedpath})
	if err != nil {
		fmt.Println(err)
		ch.Close()
		os.Exit(1)
	}
	dec := gob.NewDecoder(ch)
	var fr *FileReq
	for {
		err := dec.Decode(&fr)
		if err != nil {
			fmt.Println(err)
			continue
		}
		if fr.Path == hashedpath {
			defer ch.Close()
			f, err := os.Open(path)
			if err != nil {
				fmt.Fprintln(ch, "Sharethis error")
				os.Exit(1)
			}
			io.Copy(ch, f)
			return
		}
	}
}

func PublicKeyFile(file string) (ssh.AuthMethod, error) {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Couldn't read key file: %v", err)
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, fmt.Errorf("Couldn't parse key file: %v", err)
	}
	return ssh.PublicKeys(key), nil
}

func SSHAgent() ssh.AuthMethod {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	} else {
		fmt.Println(err)
		os.Exit(1)
	}
	return nil
}

func runServer(host, port, keyfile string) {
	filemap := map[string]*ssh.Channel{}

	cfg := buildCfg()

	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := ioutil.ReadFile(keyfile)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to load private key (%s): %v", keyfile, err))
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to parse private key: %v", err))
	}
	cfg.AddHostKey(private)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				log.Fatal("failed to accept incoming connection: ", err)
			}

			serverConn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)

			if err != nil {
				log.Fatal("failed to handshake: ", err)
			}
			// The incoming Request channel must be serviced.
			go ssh.DiscardRequests(reqs)

			// Service the incoming Channel channel.
			go func() {
				for newChannel := range chans {
					channel, requests, err := newChannel.Accept()
					if err != nil {
						log.Fatalf("Could not accept channel: %v", err)
					}

					go func(in <-chan *ssh.Request) {
						for req := range in {
							req.Reply(true, nil)
						}
					}(requests)

					go func() {
						dec := gob.NewDecoder(channel)
						var filereq FileReq

						for {
							err := dec.Decode(&filereq)
							if err != nil {
								continue
							}
							filemap[filereq.Path] = &channel
							go func() { serverConn.Wait(); delete(filemap, filereq.Path) }()
							return
						}
					}()
				}
			}()
		}
	}()
	http.ListenAndServe(":8888", http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		fp := strings.TrimPrefix(req.URL.Path, "/")
		if channel, ok := filemap[fp]; ok {
			defer func() { (*channel).Close() }()
			enc := gob.NewEncoder(*channel)
			err := enc.Encode(&FileReq{fp})
			if err != nil {
				fmt.Fprintln(rw, err)
				return
			}
			io.Copy(rw, *channel)
			delete(filemap, fp)

			return
		} else {
			rw.WriteHeader(http.StatusNotFound)
			return
		}
	}))
	os.Exit(0)

}

func buildCfg() *ssh.ServerConfig {
	authorizedKeysBytes, err := ioutil.ReadFile("authorized_keys")
	if err != nil {
		log.Fatalf("Failed to load authorized_keys, err: %v", err)
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			log.Fatal(err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	//ssh serverstuffs
	cfg := &ssh.ServerConfig{}
	cfg.SetDefaults()
	cfg.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, fmt.Errorf("Public key only") }
	cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if authorizedKeysMap[string(key.Marshal())] {
			return nil, nil
		}
		return nil, fmt.Errorf("unknown public key for %q", conn.User())
	}
	return cfg
}
