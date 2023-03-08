package ipcert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

type CertPack struct {
	CommonName         string // IPv4 address
	PrivateKey         *rsa.PrivateKey
	CertificateRequest string // pem format
	Certificate        string // pem format
	CABundle           string // pem format
}

func newCertPack(ip string) (*CertPack, error) {
	c := &CertPack{}
	var err error
	// generate a new private key
	c.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// create a CSR using the template and private key
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         ip,
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
			Organization:       []string{"Hello Pty Ltd"},
			OrganizationalUnit: []string{"Cloud"},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %v", err)
	}

	// encode the CSR in PEM format
	c.CertificateRequest = string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}))
	return c, nil
}
