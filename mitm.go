package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/fatih/color"
)

func main() {
	type config struct {
		connectURL string
		listenURL  string
	}
	var cfg config
	flag.StringVar(&cfg.listenURL, "listen", "", "hostname to listen to, in the form of: host:port")
	flag.StringVar(&cfg.connectURL, "connect", "", "url to connect to, in the form of: host:port")
	flag.Parse()

	remoteHost := strings.Split(cfg.connectURL, ":")
	if len(remoteHost) != 2 {
		panic("wrong -connect parameter, must be: host:port")
	}

	cert := generateSelfSignedCert(remoteHost[0])

	l, err := tls.Listen("tcp", cfg.listenURL, &tls.Config{
		Certificates: []tls.Certificate{
			cert,
		},
	})
	if err != nil {
		panic(err)
	}

	var clientID int
	for {
		conn, err := l.Accept()
		if err != nil {
			panic(err)
		}

		clientID++
		go handle(conn, remoteHost, clientID)
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

func handle(conn net.Conn, remoteHost []string, clientID int) {
	// ignoring error on close for now
	defer conn.Close()

	remoteConn, err := tls.Dial("tcp", strings.Join(remoteHost, ":"), &tls.Config{
		ServerName: remoteHost[0],
	})
	if err != nil {
		panic(err)
	}

	colorIndex := (clientID % 8) + int(color.FgBlack)
	c := color.New(color.Attribute(colorIndex))

	log.Printf(c.Sprintf("| %3d | ==m-- | %s", clientID, "connected to remote"))

	go handleRemote(conn, remoteConn, clientID, c)

	s := bufio.NewScanner(conn)

	for s.Scan() {

		log.Printf(c.Sprintf("| %3d | =>m   | %s", clientID, s.Text()))

		_, err = remoteConn.Write(append(s.Bytes(), '\n'))
		if err != nil {
			panic(err)
		}
		log.Printf(c.Sprintf("| %3d |   m-> | %s", clientID, s.Text()))
	}
}

func handleRemote(conn net.Conn, remoteConn net.Conn, clientID int, c *color.Color) {
	// ignoring error on close for now
	defer conn.Close()

	//r := bufio.NewReader(remoteConn)
	s := bufio.NewScanner(remoteConn)

	for s.Scan() {
		log.Printf(c.Sprintf("| %3d |   m<- | %s", clientID, s.Text()))

		_, err := conn.Write(append(s.Bytes(), '\n'))
		if err != nil {
			panic(err)
		}
		log.Printf(c.Sprintf("| %3d | <=m   | %s", clientID, s.Text()))
	}

}
