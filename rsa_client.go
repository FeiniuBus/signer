package signer

type RSAClient interface {
	Sign(input []byte) ([]byte, string, error)
	ASN1Sign(typ string, payloads ...string) ([]byte, string, error)
	StringsSign(separator string, payloads ...string) ([]byte, string, error)
}
