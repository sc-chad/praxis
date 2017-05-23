package local

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

func (p *Provider) createCA() error {
	if p.storageExists("system.ca.public") {
		return nil
	}

	cert, err := generateCACertificate(p.Name)
	if err != nil {
		return err
	}

	for _, c := range cert.Certificate {
		fmt.Printf("string(c) = %+v\n", string(c))
	}

	return nil
}

func generateCACertificate(host string) (tls.Certificate, error) {
	rkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:         true,
		DNSNames:     []string{host},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"convox"},
		},
	}

	data, err := x509.CreateCertificate(rand.Reader, &template, &template, &rkey.PublicKey, rkey)
	if err != nil {
		return tls.Certificate{}, err
	}

	pub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data})
	key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rkey)})

	cert, err := tls.X509KeyPair(pub, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}
