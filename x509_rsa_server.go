package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

type x509RSAServer struct {
	rootCA   RSACert
	workpath string
}

func Newx509RSAServer(rootCA RSACert) (RSAServer, error) {
	w := &x509RSAServer{
		rootCA: rootCA,
	}
	_, err := w.UseHomeDir()
	if err != nil {
		return nil, err
	}
	return w, nil
}

func Newx509RSAServerFrom(privateKeyUrl string, rootCertificateUrl string) (RSAServer, error) {
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

	return Newx509RSAServer(rootCA)

}

func (w *x509RSAServer) UseHomeDir() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}
	path := filepath.Join(currentUser.HomeDir, ".feiniubus", "signer", "privatekeys")
	w.SetWorkPath(path)
	return path, nil
}

func (w *x509RSAServer) SetWorkPath(absolutePath string) {
	w.workpath = absolutePath
}

func (w *x509RSAServer) CreateClient(p *rsa.PrivateKey) RSAClient {

	project := &x509RSAClient{
		rootCA: w.rootCA,
		priKey: p,
	}
	return project
}

func (w *x509RSAServer) CreateClientFrom(url string) (RSAClient, error) {
	priKey, err := w.loadPK(url)
	if err != nil {
		return nil, err
	}
	return w.CreateClient(priKey), nil
}

func (w *x509RSAServer) GenerateRSAPrivateKeyToURI(uri string, size int) (*rsa.PrivateKey, error) {
	accessor, err := ParseURI(uri)
	if err != nil {
		return nil, err
	}
	priKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}
	buf := x509.MarshalPKCS1PrivateKey(priKey)
	keyPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: buf,
	}
	key := pem.EncodeToMemory(keyPem)

	err = accessor.Upload(key)
	if err != nil {
		return nil, err
	}
	return priKey, nil
}

func (w *x509RSAServer) GenerateRSAPrivateKey(size int) (*rsa.PrivateKey, error) {
	today := time.Date(time.Now().Year(), time.Now().Month(), 1, 0, 0, 0, 0, time.Local)
	p := filepath.Join(w.workpath, fmt.Sprintf("%d.pem", today.Unix()))
	if _, err := os.Stat(p); os.IsExist(err) {
		pk, err := w.loadPK(p)
		if err != nil {
			return nil, err
		}
		return pk, nil
	}
	pk, err := w.GenerateRSAPrivateKeyToURI(p, size)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func (w *x509RSAServer) loadPK(uri string) (*rsa.PrivateKey, error) {
	accessor, err := ParseURI(uri)
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
	return priKey, nil
}
