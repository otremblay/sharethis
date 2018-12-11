package sharethis // import "github.com/otremblay/sharethis"

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

type FileReq struct {
	Path       string
	ShareCount uint
	Username   string
	Hostname   string
	ServerConn *ssh.ServerConn
	fileurl    string
	httpport   string
	remotehost string
	localpath  string
	filename   string
	IsDir      bool
}

func NewFileReq(path, httpport, remotehost string, shareCount uint) *FileReq {
	return getFileReq(DefaultPrefixFn, path, httpport, remotehost, shareCount)
}

func (fr *FileReq) RebuildUrls() {
	fr = getFileReq(DefaultPrefixFn, fr.localpath, fr.httpport, fr.remotehost, fr.ShareCount)
}

func (fr *FileReq) String() string {
	if fr.IsDir {
		return fmt.Sprintf("%s\n%s", fr.fileurl+".tar", fr.fileurl+".zip")
	} else {
		return fmt.Sprintf(fr.fileurl)
	}
}

func getRemotePath(prefixFn func() string, path string) string {
	fullpath := fmt.Sprintf("%s:%s", prefixFn(), path)
	hashedpath := fmt.Sprintf("%x", sha256.Sum256([]byte(fullpath)))
	return fmt.Sprintf("%s/%s", hashedpath, filepath.Base(path))
}

func getFileReq(prefixFn func() string, path string, httpport string, remotehost string, sharecount uint) *FileReq {
	var dir bool
	if fs, err := os.Stat(path); err != nil {
		log.Fatalln("Can't read file")
	} else {
		p, err := filepath.Abs(fs.Name())
		if err != nil {
			log.Fatalln("Can't read file")
		}
		dir = fs.IsDir()
		path = p
	}
	remotepath := getRemotePath(prefixFn, path)
	var fileurl string
	if httpport == "443" {
		fileurl = fmt.Sprintf("https://%s/%s", remotehost, remotepath)
	} else if httpport == "80" {
		fileurl = fmt.Sprintf("http://%s/%s", remotehost, remotepath)
	} else {
		fileurl = fmt.Sprintf("http://%s:%s/%s", remotehost, httpport, remotepath)
	}
	return &FileReq{Path: remotepath, ShareCount: sharecount, fileurl: fileurl, localpath: path, IsDir: dir}
}

var DefaultPrefixFn = func() string {
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not get hostname with os.Hostname()")
		hostname = "unknown"
	}
	var username string
	userobj, err := user.Current()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not get user with user.Current()")
		username = "unknown"
	} else {
		username = userobj.Username
	}
	return fmt.Sprintf("%s@%s", username, hostname)
}
