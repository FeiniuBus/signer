package signer

type RSACertIssuor interface {
	GetRootCert() RSACert
	Issue(subject *X509Subject) (RSACert, error)
}
