package signer

type RSAClient interface {
	Sign(input []byte) ([]byte, error)
	SavePrivateKeyToURI(uri string) error
	CreateCertificateToURI(uri string, subject *x509Subject) (RSACert, error)
}
