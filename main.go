package main // import "github.com/otremblay/sharethis"

import (
	"archive/tar"
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

var authorizedKeys = os.Getenv("SHARETHIS_AUTHORIZEDKEYS")

func main() {
	bg := flag.Bool("bg", false, "sends the process in the background")
	server := flag.Bool("server", false, "makes the process an http server")
	remotehost := flag.String("remote", "share.otremblay.com", "remote server for sharethis to contact")
	sshport := flag.String("sshport", "2022", "the remote ssh port")
	httpport := flag.String("httpport", "8888", "the remote server's http port")
	sharecount := flag.Uint("count", 1, "Amount of times you want to share this file")
	serverkey := flag.String("serverkey", "id_rsa", "Path to the server private key")
	flag.Parse()
	if envsshport := os.Getenv("SHARETHIS_SSHPORT"); envsshport != "" {
		*sshport = envsshport
	}
	if envhttpport := os.Getenv("SHARETHIS_HTTPPORT"); envhttpport != "" {
		*httpport = envhttpport
	}
	if envremotehost := os.Getenv("SHARETHIS_REMOTEHOST"); envremotehost != "" {
		*remotehost = envremotehost
	}
	if authorizedKeys == "" {
		authorizedKeys = fmt.Sprintf("%s/.ssh/authorized_keys", os.ExpandEnv("HOME"))
	}
	if *sharecount > 0 {
		*sharecount--
	}
	if *server {
		if envserverkey := os.Getenv("SHARETHIS_SERVERKEY"); envserverkey != "" {
			*serverkey = envserverkey
		}
		runServer("0.0.0.0", *sshport, *httpport, *serverkey)
	}
	if len(flag.Args()) < 1 {
		log.Fatalln("Need filename")
	}
	var path string
	var dir bool
	var name string
	if fs, err := os.Stat(flag.Arg(0)); err != nil {
		log.Fatalln("Can't read file")
	} else {
		name = fs.Name()
		p, err := filepath.Abs(fs.Name())
		if err != nil {
			log.Fatalln("Can't read file")
		}
		path = p
		dir = fs.IsDir()
	}

	if *bg {
		_, err := syscall.ForkExec(os.Args[0], append([]string{os.Args[0]}, flag.Args()...), &syscall.ProcAttr{Files: []uintptr{0, 1, 2}})
		if err != nil {
			log.Fatalln(err)
		}
		os.Exit(0)
	}
	var username string
	userobj, err := user.Current()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not get user with user.Current()")
		username = "unknown"
	} else {
		username = userobj.Username
	}

	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	if agent, err := SSHAgent(); err == nil {
		sshConfig.Auth = append(sshConfig.Auth, agent)
	}

	keypath := fmt.Sprintf("%s/.ssh/st_rsa", os.Getenv("HOME"))
	auth, err := PublicKeyFile(keypath)
	if err != nil {
		fmt.Println(err)
	} else {
		sshConfig.Auth = append(sshConfig.Auth, auth)
	}

	connection, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", *remotehost, *sshport), sshConfig)
	if err != nil {
		log.Fatalln("Failed to dial: %s", err)
	}

	ch, reqch, err := connection.OpenChannel("Nope", nil)
	go ssh.DiscardRequests(reqch)
	if err != nil {
		log.Fatalln("poop", err)
	}
	enc := gob.NewEncoder(ch)
	path = flag.Arg(0)

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not get hostname with os.Hostname()")
		hostname = "unknown"
	}
	fullpath := fmt.Sprintf("%s@%s:%s", username, hostname, path)
	hashedpath := fmt.Sprintf("%x", sha256.Sum256([]byte(fullpath)))

	// In the words of weezer, I've got my hashed path.
	// TODO: Get the remote URL from the remote server instead of rebuilding it locally.
	var fileurl string
	fullpath = fmt.Sprintf("%s/%s", hashedpath, name)
	if *httpport == "443" {
		fileurl = fmt.Sprintf("https://%s/%s", *remotehost, fullpath)
	} else if *httpport == "80" {
		fileurl = fmt.Sprintf("http://%s/%s", *remotehost, fullpath)
	} else {
		fileurl = fmt.Sprintf("http://%s:%s/%s", *remotehost, *httpport, fullpath)
	}

	if dir {
		fmt.Println(fileurl + ".tar")
		fmt.Println(fileurl + ".zip")
	} else {
		fmt.Println(fileurl)
	}

	err = enc.Encode(&FileReq{Path: fullpath, ShareCount: *sharecount})
	if err != nil {
		fmt.Println(err)
		ch.Close()
		os.Exit(1)
	}

	mu := &sync.Mutex{}

	defer ch.Close()
	var getchfn func() ssh.NewChannel
	if dir {
		ncc := connection.HandleChannelOpen(fullpath + ".tar")
		ncc2 := connection.HandleChannelOpen(fullpath + ".zip")
		getchfn = func() ssh.NewChannel {
			select {
			case nc := <-ncc:
				return nc
			case nc := <-ncc2:
				return nc
			}
		}

	} else {
		ncc := connection.HandleChannelOpen(fullpath)
		getchfn = func() ssh.NewChannel {
			return <-ncc
		}
	}

	for {
		nc := getchfn()
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
			if fs, _ := f.Stat(); fs.IsDir() {
				tw := tar.NewWriter(ch)
				err := WriteFiles(tw, fs, ".")
				if err != nil {
					fmt.Fprintln(ch, "Error building tar", err)
				}
				tw.Close()
				mu.Lock()
				if *sharecount == 0 {
					mu.Unlock()
					os.Exit(0)
				}
				*sharecount--
				mu.Unlock()
				ch.Close()

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

func WriteFiles(tw *tar.Writer, fi os.FileInfo, path string) error {
	p := path + "/" + fi.Name()
	f, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("Couldn't write files: %v", err)
	}
	if fs, _ := f.Stat(); fs.IsDir() {
		fis, err := f.Readdir(-1)
		if err != nil {
			return fmt.Errorf("Couldn't enumerate dir: %v", err)
		}
		var cumulerror error
		for _, nfi := range fis {
			err := WriteFiles(tw, nfi, p)
			if err != nil {
				cumulerror = fmt.Errorf("%vCouldn't write files for %s: %v\n", cumulerror, nfi.Name(), err)
			}
		}
		return cumulerror
	}
	hdr, err := tar.FileInfoHeader(fi, "")
	hdr.Name = p
	if err != nil {
		return fmt.Errorf("Couldn't build tar header: %v", err)
	}

	err = tw.WriteHeader(hdr)
	if err != nil {
		return fmt.Errorf("Couldn't write tar header: %v", err)
	}
	_, err = io.Copy(tw, f)
	return err
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

func SSHAgent() (ssh.AuthMethod, error) {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		a := agent.NewClient(sshAgent)
		signers, _ := a.Signers()
		if len(signers) == 0 {
			return nil, fmt.Errorf("No signer found")
		}
		return ssh.PublicKeysCallback(a.Signers), nil
	} else {
		fmt.Println(err)
		return nil, err
	}
	return nil, nil
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
				log.Println("failed to accept incoming connection: ", err)
				continue
			}

			serverConn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)

			if err != nil {
				log.Println("failed to handshake: ", err)
				continue
			}
			// The incoming Request channel must be serviced.
			go ssh.DiscardRequests(reqs)

			// Service the incoming Channel channel.
			go func() {
				for newChannel := range chans {
					channel, requests, err := newChannel.Accept()
					if err != nil {
						log.Println("Could not accept channel: ", err)
						continue
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
		var suffix string
		if strings.HasSuffix(fp, ".zip") {
			suffix = ".zip"
			fp = strings.TrimSuffix(fp, ".zip")
		}
		if strings.HasSuffix(fp, ".tar") {
			suffix = ".tar"
			fp = strings.TrimSuffix(fp, ".tar")
		}
		fp = strings.TrimSuffix(fp, ".tar")
		if fr, ok := mapget(fp); ok {
			channel, req, err := fr.serverconn.OpenChannel(fp+suffix, nil)
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
	authorizedKeysBytes, err := ioutil.ReadFile(authorizedKeys)
	if err != nil {
		log.Fatalf("Failed to load authorized_keys, err: %v", err)
	}

	authorizedKeysMap := map[string]string{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, comment, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		fmt.Println(comment)
		if err != nil {
			log.Fatal("authorized_keys error", err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = comment
		authorizedKeysBytes = rest
	}

	//ssh serverstuffs
	cfg := &ssh.ServerConfig{}
	cfg.SetDefaults()
	cfg.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, fmt.Errorf("Public key only") }
	cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if user, ok := authorizedKeysMap[string(key.Marshal())]; ok {
			fmt.Println("Key used:", user)
			return nil, nil
		}
		return nil, fmt.Errorf("unknown public key for %q", conn.User())
	}
	return cfg
}
