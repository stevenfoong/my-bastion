// mybastion-dbproxy: the database access proxy of My Bastion (Phase 4 of
// docs/fork-design.md). PostgreSQL clients (psql, DBeaver, ...) connect to
// it over TLS with a bastion DB token as the password; it fetches the real
// credentials from the core, checks every statement with the core's
// db_query policies, and sends each statement's outcome to the core's
// audit log. See docs/database-proxy.md.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

func main() {
	listen := flag.String("listen", ":5433", "address to listen on")
	coreURL := flag.String("core", "http://127.0.0.1:8089", "the bastion core's URL")
	secretFile := flag.String("secret-file", "/etc/mybastion/dbproxy-secret", "file with the shared secret ([dbproxy] shared_secret_file in the core)")
	certFile := flag.String("tls-cert", "/etc/mybastion/tls/cert.pem", "TLS certificate for clients")
	keyFile := flag.String("tls-key", "/etc/mybastion/tls/key.pem", "TLS key for clients")
	coreCA := flag.String("core-ca", "", "PEM certificate(s) to trust for an https -core (e.g. the core's own self-signed cert)")
	flag.Parse()

	secret, err := os.ReadFile(*secretFile)
	if err != nil {
		logger.Error("cannot read the shared secret", "file", *secretFile, "error", err)
		os.Exit(1)
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		logger.Error("cannot load the TLS certificate", "error", err)
		os.Exit(1)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if *coreCA != "" {
		pem, err := os.ReadFile(*coreCA)
		if err != nil {
			logger.Error("cannot read -core-ca", "file", *coreCA, "error", err)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			logger.Error("no certificate in -core-ca", "file", *coreCA)
			os.Exit(1)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	core := &Core{
		URL:    strings.TrimRight(*coreURL, "/"),
		Secret: strings.TrimSpace(string(secret)),
		HTTP:   &http.Client{Timeout: 20 * time.Second, Transport: transport},
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Error("cannot listen", "address", *listen, "error", err)
		os.Exit(1)
	}
	logger.Info("mybastion-dbproxy listening", "address", ln.Addr().String(), "core", core.URL)
	for {
		c, err := ln.Accept()
		if err != nil {
			logger.Warn("accept", "error", err)
			continue
		}
		go handle(c, core, tlsCfg)
	}
}
