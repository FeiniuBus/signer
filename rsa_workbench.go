package signer

import "crypto/rsa"

type RSAWorkbench interface {
	CreateProject(p *rsa.PrivateKey, subject *x509Subject) (RSAProject, error)
	CreateProjectFrom(url string, subject *x509Subject) (RSAProject, error)
}
