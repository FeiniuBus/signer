package signer

type RSAProject interface {
	Sign(input []byte) ([]byte, error)
	SavePrivateKeyTo(uri string) error
	SaveCertificateTo(uri string) error
}
