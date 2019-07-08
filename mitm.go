package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"
)

var remoteURL string

func main() {
	remoteURL = os.Getenv("MITM_REMOTE_URL")
	url, err := url.Parse(remoteURL)
	if err != nil {
		panic(err)
	}

	cert := generateSelfSignedCert(url.Hostname())

	l, err := tls.Listen("tcp", ":9999", &tls.Config{
		Certificates: []tls.Certificate{
			cert,
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
		go handle(conn, url.Hostname())
	}
}

func generateSelfSignedCert(remoteHostname string) tls.Certificate {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber:          big.NewInt(now.Unix()),
		Subject:               pkix.Name{Organization: []string{"Listening Partner Inc."}},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.DNSNames = append(template.DNSNames, remoteHostname)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func handle(conn net.Conn, remoteHostname string) {
	fmt.Println("somebody connected")
	// ignoring error on close for now
	defer conn.Close()

	remoteConn, err := tls.Dial("tcp", remoteURL, &tls.Config{
		ServerName: remoteHostname,
	})
	if err != nil {
		panic("you" + err.Error())
	}
	log.Println("connected to remote", remoteURL)

	go handleRemote(conn, remoteConn)

	s := bufio.NewScanner(conn)

	for s.Scan() {

		log.Println("⇒m  :", s.Text())

		_, err = remoteConn.Write(append(s.Bytes(), '\n'))
		if err != nil {
			panic(err)
		}
		log.Println("  m→:", string(s.Text()))
	}
}

func handleRemote(conn net.Conn, remoteConn net.Conn) {
	// ignoring error on close for now
	defer conn.Close()

	//r := bufio.NewReader(remoteConn)
	s := bufio.NewScanner(remoteConn)

	for s.Scan() {
		log.Println("  m←:", s.Text())

		_, err := conn.Write(append(s.Bytes(), '\n'))
		if err != nil {
			panic(err)
		}
		log.Println("⇐m  :", s.Text())
	}

}
