package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"time"
)

type x509RSATestStore struct {
	rootCert RSACert
	subject  *X509Subject
	priKey   *rsa.PrivateKey
	expire   time.Time
	mu       sync.Mutex
	source   *RSADescriptorCollection
	tag      string
}

func (s *x509RSATestStore) SetTag(tag string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tag = tag
}

func (s *x509RSATestStore) Tag() string {
	return s.tag
}

func (s *x509RSATestStore) Certificate(clientID string) (RSADescriptor, error) {
	if s.expire.Unix() > time.Now().Unix() && s.source.AnyClientID(clientID) {
		return s.source.FirstClientID(clientID), nil
	}
	if s.expire.Unix() <= time.Now().Unix() {
		err := func() error {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.expire.Unix() <= time.Now().Unix() {
				priKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return err
				}
				s.priKey = priKey
				s.expire = time.Now().Add(time.Hour * 24 * 7)
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.source.AnyClientID(clientID) {
		return s.source.FirstClientID(clientID), nil
	}
	issuor := Newx509RSACertIssuor(s.rootCert, s.priKey)
	_, err := issuor.Issue(s.subject)
	if err != nil {
		return nil, err
	}

	descriptor := Newx509RSADescriptor(clientID, "", s.priKey)
	s.source.AddOrReplace(descriptor)

	return descriptor, nil
}
