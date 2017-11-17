package signer

import (
	"encoding/base64"
	"testing"
)

var store RSAStore

func Test_RSAServer(t *testing.T) {
	root, err := Parsex509RSACert(getRootCA(), getRootKey())
	if err != nil {
		t.Fatal(err)
	}

	factory := NewRSAStoreFactory("test", "polaris/Certificates", root, GetDefaultSubject())
	store, err := factory.Create(x509RSAStore_OneToMany)
	if err != nil {
		t.Fatal(err)
	}

	server := Newx509RSAServer(store)
	client, err := server.CreateClient("test_client")
	if err != nil {
		t.Fatal(err)
	}

	signature, url, err := client.Sign([]byte("testing"))
	t.Log(base64.StdEncoding.EncodeToString(signature))
	t.Log(url)
}
