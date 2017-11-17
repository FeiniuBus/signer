package signer

import (
	"crypto/x509"
	"time"
)

type X509Subject struct {
	Country            []string
	Orianization       []string
	OrianizationalUnit []string
	Province           []string
	CommonName         string
	Locality           []string
	NotBefore          time.Time
	NotAfter           time.Time
	ExtKeyUsage        []x509.ExtKeyUsage
	KeyUsage           x509.KeyUsage
	IsRoot             bool
}

func GetDefaultSubject() *X509Subject {
	return &X509Subject{
		Country:            []string{"CN"},
		Orianization:       []string{"FEINIUBUS"},
		OrianizationalUnit: []string{"CITADEL"},
		Province:           []string{"SICHUAN"},
		CommonName:         "CITADEL AUTH",
		Locality:           []string{"CHENGDU"},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Hour * 24 * 30),
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		IsRoot:             false,
	}
}
