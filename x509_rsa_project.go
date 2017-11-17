package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type x509RSAProject struct {
	rootCA RSACert
	priKey *rsa.PrivateKey
}

func (p *x509RSAProject) Sign(input []byte) ([]byte, error) {
	signer := Newx509RSASigner()
	return signer.Sign(input, p.priKey)
}

func (p *x509RSAProject) SavePrivateKeyToURI(uri string) error {
	accessor, err := ParseURI(uri)
	if err != nil {
		return err
	}

	buf := x509.MarshalPKCS1PrivateKey(p.priKey)
	keyPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: buf,
	}
	key := pem.EncodeToMemory(keyPem)

	err = accessor.Upload(key)
	if err != nil {
		return err
	}
	return nil
}

func (p *x509RSAProject) CreateCertificateToURI(uri string, subject *x509Subject) (RSACert, error) {
	issuor := Newx509RSACertIssuor(p.rootCA, p.priKey)
	issueSubject := subject
	if issueSubject == nil {
		issueSubject = GetDefaultSubject()
	}
	cert, err := issuor.Issue(issueSubject)
	if err != nil {
		return nil, err
	}
	return cert, err
}
