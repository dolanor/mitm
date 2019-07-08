package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
)

var remoteURL string

func main() {
	remoteURL = os.Getenv("MITM_REMOTE_URL")

	kp, err := tls.LoadX509KeyPair("/home/dolanor/cert.pem", "/home/dolanor/key.pem")
	if err != nil {
		panic(err)
	}

	l, err := tls.Listen("tcp", ":9999", &tls.Config{
		Certificates: []tls.Certificate{
			kp,
		},
	})
	if err != nil {
		panic(err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			panic(err)
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	fmt.Println("somebody connected")
	// ignoring error on close for now
	defer conn.Close()

	remoteConn, err := tls.Dial("tcp", remoteURL, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "mail.evereska.org",
	})
	if err != nil {
		panic("you" + err.Error())
	}
	log.Println("connected to remote", remoteURL)

	go handleRemote(conn, remoteConn)

	r := bufio.NewReader(conn)

	for {
		cmd, _, err := r.ReadLine()
		if err != nil {
			panic(err)
		}
		log.Println("⇒m  :", string(cmd))

		_, err = remoteConn.Write([]byte(append(cmd, '\n')))
		if err != nil {
			panic(err)
		}
		log.Println("  m→:", string(cmd))
	}
}

func handleRemote(conn net.Conn, remoteConn net.Conn) {
	// ignoring error on close for now
	defer conn.Close()

	r := bufio.NewReader(remoteConn)

	for {
		cmd, _, err := r.ReadLine()
		if err != nil {
			panic(err)
		}
		log.Println("  m←:", string(cmd))

		_, err = conn.Write([]byte(append(cmd, '\n')))
		if err != nil {
			panic(err)
		}
		log.Println("⇐m  :", string(cmd))
	}

}
