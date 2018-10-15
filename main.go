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
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type FileReq struct {
	Path       string
	ShareCount uint
	serverconn *ssh.ServerConn
}

func main() {
	bg := flag.Bool("bg", false, "sends the process in the background")
	server := flag.Bool("server", false, "makes the process an http server")
	remotehost := flag.String("remote", "share.otremblay.com", "remote server for sharethis to contact")
	sshport := flag.String("sshport", "2022", "the remote ssh port")
	httpport := flag.String("httpport", "8888", "the remote server's http port")
	sharecount := flag.Uint("count", 1, "Amount of times you want to share this file")
	flag.Parse()
	if *server {
		runServer("0.0.0.0", *sshport, *httpport, "id_rsa")
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
	connection, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", *remotehost, *sshport), sshConfig)
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
	// TODO: Get the remote URL from the remote server instead of rebuilding it locally.
	// TODO: Clean up the port from the URL if it's 80 or 443
	var fileurl string
	if *httpport == "443" {
		fileurl = fmt.Sprintf("https://%s/%s", *remotehost, hashedpath)
	} else if *httpport == "80" {
		fileurl = fmt.Sprintf("http://%s/%s", *remotehost, hashedpath)
	} else {
		fileurl = fmt.Sprintf("http://%s:%s/%s", *remotehost, *httpport, hashedpath)
	}
	fmt.Println(fileurl)
	err = enc.Encode(&FileReq{Path: hashedpath, ShareCount: *sharecount})
	if err != nil {
		fmt.Println(err)
		ch.Close()
		os.Exit(1)
	}

	mu := &sync.Mutex{}

	defer ch.Close()
	ncc := connection.HandleChannelOpen(hashedpath)
	for {
		nc := <-ncc
		ch, req, err := nc.Accept()
		go ssh.DiscardRequests(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}

		go func() {
			f, err := os.Open(path)
			if err != nil {
				fmt.Fprintln(ch, "Sharethis error")
				return
			}
			_, err = io.Copy(ch, f)
			if err != nil {
				fmt.Println(err)
				return
			}
			mu.Lock()
			if *sharecount == 0 {
				mu.Unlock()
				os.Exit(0)
			}
			*sharecount--
			mu.Unlock()
			ch.Close()
		}()

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

func runServer(host, sshport, httpport, keyfile string) {
	filemap := map[string]*FileReq{}
	syncy := &sync.RWMutex{}

	mapget := func(key string) (*FileReq, bool) {
		syncy.RLock()
		defer syncy.RUnlock()
		c, ok := filemap[key]
		return c, ok
	}
	mapset := func(key string, fr *FileReq) {
		syncy.Lock()
		filemap[key] = fr
		syncy.Unlock()
	}
	mapdel := func(key string) {
		syncy.Lock()
		delete(filemap, key)
		syncy.Unlock()
	}

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

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", host, sshport))
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

							// TODO: also take the sharecount in the map.
							filereq.serverconn = serverConn
							mapset(filereq.Path, &filereq)
							go func() { serverConn.Wait(); mapdel(filereq.Path) }()
							return
						}
					}()
				}
			}()
		}
	}()
	http.ListenAndServe(fmt.Sprintf(":%s", httpport), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.UserAgent(), "Slackbot-LinkExpanding") {
			rw.WriteHeader(http.StatusForbidden)
			fmt.Fprintln(rw, "No slackbots allowed!")
			return
		}
		fp := strings.TrimPrefix(req.URL.Path, "/")
		if fr, ok := mapget(fp); ok {
			channel, req, err := fr.serverconn.OpenChannel(fp, nil)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			go ssh.DiscardRequests(req)

			_, err = io.Copy(rw, channel)
			if err != nil {
				fmt.Println(err)
			}
			if fr.ShareCount == 0 {
				mapdel(fp)
				channel.Close()
			}
			fr.ShareCount--
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

	authorizedKeysMap := map[string]string{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, comment, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		fmt.Println(comment)
		if err != nil {
			log.Fatal(err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = comment
		authorizedKeysBytes = rest
	}

	//ssh serverstuffs
	cfg := &ssh.ServerConfig{}
	cfg.SetDefaults()
	cfg.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, fmt.Errorf("Public key only") }
	cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if _, ok := authorizedKeysMap[string(key.Marshal())]; ok {
			return nil, nil
		}
		return nil, fmt.Errorf("unknown public key for %q", conn.User())
	}
	return cfg
}
