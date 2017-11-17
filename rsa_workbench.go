package signer

import "crypto/rsa"

type RSAWorkbench interface {
	CreateProject(p *rsa.PrivateKey) RSAProject
	CreateProjectFrom(url string) (RSAProject, error)
	GenerateRSAPrivateKey(size int) (*rsa.PrivateKey, error)
}
