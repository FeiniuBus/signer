package signer

import (
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"
)

var store RSAStore

func DISABLETest_RSAServer(t *testing.T) {
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

	time.Sleep(time.Second * 3)
}

func DISABLETest_RSAServerParallel(t *testing.T) {
	root, err := Parsex509RSACert(getRootCA(), getRootKey())
	if err != nil {
		t.Fatal(err)
	}

	factory := NewRSAStoreFactory("test", "polaris/Certificates", root, GetDefaultSubject())
	store, err := factory.Create(x509RSAStore_OneToMany)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup

	f := func(clientID string) {
		server := Newx509RSAServer(store)
		client, err := server.CreateClient(clientID)
		if err != nil {
			t.Fatal(err)
		}

		signature, url, err := client.Sign([]byte("testing"))
		t.Log(base64.StdEncoding.EncodeToString(signature))
		t.Log(url)
		wg.Done()
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go f(fmt.Sprintf("test_client_%d", i))
	}

	wg.Wait()
}
