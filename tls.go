package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

type HTTPRequest struct {
	Method string
	Host   string
	Path   string
	Body   string
}

func (r HTTPRequest) String() string {
	return fmt.Sprintf("%s %s%s", r.Method, r.Host, r.Path)
}

type connResponseWriter struct {
	conn       net.Conn
	req        *http.Request
	header     http.Header
	statusCode int
	body       []byte
}

func newConnResponseWriter(conn net.Conn, req *http.Request) *connResponseWriter {
	return &connResponseWriter{
		conn:       conn,
		req:        req,
		header:     make(http.Header),
		statusCode: http.StatusOK,
	}
}

func (w *connResponseWriter) Header() http.Header {
	return w.header
}

func (w *connResponseWriter) WriteHeader(code int) {
	w.statusCode = code
}

func (w *connResponseWriter) Write(data []byte) (int, error) {
	w.body = append(w.body, data...)
	return len(data), nil
}

func (w *connResponseWriter) flush() {
	resp := &http.Response{
		StatusCode:    w.statusCode,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        w.header,
		ContentLength: int64(len(w.body)),
		Request:       w.req,
	}
	if len(w.body) > 0 {
		resp.Body = io.NopCloser(bytes.NewReader(w.body))
	}
	resp.Write(w.conn)
}

func generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Router Freedom CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

type certCache struct {
	mu    sync.Mutex
	certs map[string]*tls.Certificate
}

func newCertCache() *certCache {
	return &certCache{certs: make(map[string]*tls.Certificate)}
}

func (c *certCache) get(hostname string, ca *x509.Certificate, caKey *rsa.PrivateKey) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if cert, ok := c.certs[hostname]; ok {
		return cert, nil
	}

	cert, err := certForHost(hostname, ca, caKey)
	if err != nil {
		return nil, err
	}
	c.certs[hostname] = cert
	return cert, nil
}

func certForHost(hostname string, ca *x509.Certificate, caKey *rsa.PrivateKey) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{hostname}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

func (s *Session) handleTLS(conn net.Conn) {
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			hostname := hello.ServerName
			if hostname == "" {
				hostname = "unknown"
			}
			log.Printf("TLS ClientHello SNI: %s", hostname)
			s.addSNIHost(hostname)
			return s.certCache.get(hostname, s.ca, s.caKey)
		},
	}

	tlsConn := tls.Server(conn, tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}

	tr := newTR069Session()
	reader := bufio.NewReader(tlsConn)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		var body string
		if req.Body != nil {
			bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, 1024*1024))
			req.Body.Close()
			if err == nil {
				body = string(bodyBytes)
			}
		}

		host := req.Host
		if host == "" {
			host = tlsConn.ConnectionState().ServerName
		}

		httpReq := HTTPRequest{
			Method: req.Method,
			Host:   host,
			Path:   req.URL.Path,
			Body:   body,
		}
		log.Printf("HTTP request: %s\n%s", httpReq, body)
		s.addHTTPRequest(httpReq)

		rw := newConnResponseWriter(tlsConn, req)
		tr.handleRequest(body, rw)
		rw.flush()

		if tr.state == tr069Done {
			s.addTR069Params(tr.params)
			return
		}
	}
}
