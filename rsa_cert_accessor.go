package signer

type RSACertAccessor interface {
	Upload(body []byte) (string, error)
	Download() ([]byte, error)
}
