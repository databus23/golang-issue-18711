// A repro for https://github.com/golang/go/issues/18711
//

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"

	"golang.org/x/crypto/ssh"
)

type exitStatusRequest struct {
	ExitStatus uint32
}

var concurrentClients = 20
var privateKeyFile = "./test_id_rsa"

func main() {

	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		output, err := exec.Command("ssh-keygen", "-t", "rsa", "-N", "", "-f", privateKeyFile).CombinedOutput()
		if err != nil {
			log.Fatal("Failed to generate key: ", err)
		}
		log.Print(string(output))
	}

	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		log.Fatal("Failed to load private key ", privateKeyFile)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	certChecker := &ssh.CertChecker{
		IsAuthority: func(key ssh.PublicKey) bool {
			return false
		},
		UserKeyFallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(private.PublicKey().Marshal(), key.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unknown public key")
		},
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return certChecker.Authenticate(conn, key)
		},
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2200")
	if err != nil {
		log.Fatalf("Failed to listen on 2200 (%s)", err)
	}
	// Accept all connections
	log.Print("Listening on 2200...")

	log.Printf("Starting %d concurrent clients", concurrentClients)
	for i := 1; i <= concurrentClients; i++ {
		go sshClientLoop()
	}
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		_, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		//log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	for req := range requests {
		switch req.Type {
		case "exec":
			channel.Write([]byte("hello\n"))
			channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{0}))
			channel.Close()
		default:
			//log.Printf("rejecting channel request of type: %s", req.Type)
			req.Reply(false, nil)
		}
	}
}

func sshClientLoop() {
	for {
		out, err := exec.Command("ssh", "-p2200", "-oUserKnownHostsFile=/dev/null", "-oStrictHostKeyChecking=no", "-i", privateKeyFile, "localhost", "whatever").CombinedOutput()
		if err != nil {
			log.Fatal("\n", err, string(out))
		}
		fmt.Print(".")
	}
}
