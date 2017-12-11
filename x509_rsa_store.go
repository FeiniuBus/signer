package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"
)

type x509RSAOneToManyStore struct {
	rootCert RSACert
	subject  *X509Subject
	priKey   *rsa.PrivateKey
	expire   time.Time
	mu       sync.Mutex
	source   *RSADescriptorCollection
	tag      string
	bucket   string
}

func (s *x509RSAOneToManyStore) SetTag(tag string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tag = tag
}

func (s *x509RSAOneToManyStore) Tag() string {
	return s.tag
}

func (s *x509RSAOneToManyStore) Certificate(clientID string) (RSADescriptor, error) {
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
				accessor, err := ParseURI(fmt.Sprintf("files://~/.feiniubus/signer/%s_%d_%s.pem", s.Tag(), time.Now().Unix(), clientID))
				if err != nil {
					return err
				}
				buf := x509.MarshalPKCS1PrivateKey(s.priKey)
				keyPem := &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: buf,
				}
				key := pem.EncodeToMemory(keyPem)
				_, _ = accessor.Upload(key)
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
	certificate, err := issuor.Issue(s.subject)
	if err != nil {
		return nil, err
	}

	fileName := fmt.Sprintf("%s_%d_%s.crt", s.Tag(), time.Now().Unix(), clientID)

	accessor, err := ParseURI(fmt.Sprintf("s3://%s/%s?key=%s", GetS3Options().GetRegion(), s.bucket, fileName))
	if err != nil {
		return nil, err
	}

	url, err := accessor.Upload(certificate.GetCertificateBytes())
	if err != nil {
		return nil, err
	}

	descriptor := Newx509RSADescriptor(clientID, url, s.priKey)
	s.source.AddOrReplace(descriptor)

	file, err := ParseURI(fmt.Sprintf("files://~/.feiniubus/signer/%s_%d_%s.crt", s.Tag(), time.Now().Unix(), clientID))
	if err != nil {
		return nil, err
	}
	_, _ = file.Upload(certificate.GetCertificateBytes())

	return descriptor, nil
}

type X509RSAStoreMode int

const (
	_ X509RSAStoreMode = iota
	X509RSAStore_OneToMany
	X509RSAStore_Test
)

type RSAStoreFactory struct {
	rootCert RSACert
	subject  *X509Subject
	tag      string
	bucket   string
}

func NewRSAStoreFactory(tag string, bucket string, rootCert RSACert, subject *X509Subject) *RSAStoreFactory {
	return &RSAStoreFactory{
		rootCert: rootCert,
		subject:  subject,
		tag:      tag,
		bucket:   bucket,
	}
}

func NewRSAStoreFactoryFrom(tag string, bucket string, rootPriKeyUrl string, rootCertUrl string, subject *X509Subject) (*RSAStoreFactory, error) {
	rootPriKeyAccessor, err := ParseURI(rootPriKeyUrl)
	if err != nil {
		return nil, err
	}
	rootCertAccessor, err := ParseURI(rootCertUrl)
	if err != nil {
		return nil, err
	}

	rootPK, err := rootPriKeyAccessor.Download()
	if err != nil {
		return nil, err
	}
	rootCert, err := rootCertAccessor.Download()
	if err != nil {
		return nil, err
	}

	cert, err := Parsex509RSACert(rootCert, rootPK)
	if err != nil {
		return nil, err
	}

	return NewRSAStoreFactory(tag, bucket, cert, subject), nil
}

func (factory *RSAStoreFactory) Create(mode X509RSAStoreMode) (RSAStore, error) {
	if mode == X509RSAStore_OneToMany {
		return &x509RSAOneToManyStore{
			rootCert: factory.rootCert,
			subject:  factory.subject,
			tag:      factory.tag,
			bucket:   factory.bucket,
			expire:   time.Now().Add(time.Hour * -1),
			source:   NewRSADescriptorCollection(),
		}, nil
	} else if mode == X509RSAStore_Test {
		return &x509RSATestStore{
			rootCert: factory.rootCert,
			subject:  factory.subject,
			tag:      factory.tag,
			expire:   time.Now().Add(time.Hour * -1),
			source:   NewRSADescriptorCollection(),
		}, nil
	}

	return nil, errors.New("unknown mode x509RSAStoreMode")
}
