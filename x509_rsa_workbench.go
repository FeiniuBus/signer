package signer

import (
	"crypto/rand"
	"crypto/rsa"
)

type x509RSAWorkbench struct {
	rootCA RSACert
}

func Newx509RSAWorkbench(rootCA RSACert) RSAWorkbench {
	return &x509RSAWorkbench{
		rootCA: rootCA,
	}
}

func Newx509RSAWorkbenchFrom(privateKeyUrl string, rootCertificateUrl string) (RSAWorkbench, error) {
	privateKeyAccessor, err := ParseURI(privateKeyUrl)
	if err != nil {
		return nil, err
	}
	certAccessor, err := ParseURI(rootCertificateUrl)
	if err != nil {
		return nil, err
	}
	privateKeyBytes, err := privateKeyAccessor.Download()
	if err != nil {
		return nil, err
	}

	certBytes, err := certAccessor.Download()
	if err != nil {
		return nil, err
	}

	rootCA, err := Parsex509RSACert(privateKeyBytes, certBytes)
	if err != nil {
		return nil, err
	}

	return Newx509RSAWorkbench(rootCA), nil

}

func (w *x509RSAWorkbench) CreateProject(p *rsa.PrivateKey) RSAProject {

	project := &x509RSAProject{
		rootCA: w.rootCA,
		priKey: p,
	}
	return project
}

func (w *x509RSAWorkbench) CreateProjectFrom(url string) (RSAProject, error) {
	accessor, err := ParseURI(url)
	if err != nil {
		return nil, err
	}
	bytes, err := accessor.Download()
	if err != nil {
		return nil, err
	}
	priKey, err := ParseRsaPrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	return w.CreateProject(priKey), nil
}

func (w *x509RSAWorkbench) GenerateRSAPrivateKey(size int) (*rsa.PrivateKey, error) {

	priKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}
	return priKey, nil
}
