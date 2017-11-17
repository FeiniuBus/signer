package signer

import "crypto/rsa"

type RSAServer interface {
	UseHomeDir() (string, error)
	SetWorkPath(absolutePath string)
	CreateClient(p *rsa.PrivateKey) RSAClient
	CreateClientFrom(url string) (RSAClient, error)
	GenerateRSAPrivateKeyToURI(uri string, size int) (*rsa.PrivateKey, error)
	GenerateRSAPrivateKey(size int) (*rsa.PrivateKey, error)
}
