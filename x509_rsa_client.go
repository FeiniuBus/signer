package signer

import (
	"encoding/pem"
	"strings"
)

type x509RSAClient struct {
	server     RSAServer
	descriptor RSADescriptor
	clientID   string
}

func (p *x509RSAClient) Sign(input []byte) ([]byte, string, error) {
	signer := Newx509RSASigner()
	signature, err := signer.Sign(input, p.descriptor.PrivateKey())
	if err != nil {
		return nil, "", err
	}
	return signature, p.descriptor.Certificate(), nil
}

func (p *x509RSAClient) StringsSign(separator string, payloads ...string) ([]byte, string, error) {
	payload := strings.Join(payloads, separator)
	return p.Sign([]byte(payload))
}

func (p *x509RSAClient) ASN1Sign(typ string, payloads ...string) ([]byte, string, error) {
	payload := strings.Join(payloads, "\r\n")
	block := &pem.Block{
		Type:  strings.ToUpper(typ),
		Bytes: []byte(payload),
	}
	asn1Str := pem.EncodeToMemory(block)
	return p.Sign(asn1Str)
}
