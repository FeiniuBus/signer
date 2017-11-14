package signer

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/FeiniuBus/signer/credentials"
)

type body struct {
	Name string
	Age  int
}

func TestSignRequest(t *testing.T) {
	b := body{
		Name: "xqlun",
		Age:  31,
	}
	data, _ := json.Marshal(b)
	req := buildRequest(string(data))
	signer := buildSigner()

	res, err := signer.Sign(req, 10*time.Second)
	if err != nil {
		t.Errorf("Sign error: %v", err)
	}

	if date := res.Header.Get(XFeiniuBusDateHeader); len(date) <= 0 {
		t.Errorf("Can't find signature time")
	}
}

func buildRequest(body string) *Request {
	endpoint := "https://dc.feiniubus.com:5100/fns/v1/test/update?id=1232232"
	reader := strings.NewReader(body)
	request, _ := http.NewRequest("PUT", endpoint, reader)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Content-Length", string(len(body)))
	request.Header.Add("Accept", "application/json")

	req := &Request{
		Method: request.Method,
		URL:    request.URL,
		Body:   reader,
		Header: request.Header,
	}
	return req
}

func buildSigner() HMACSigner {
	return NewHMACSignerV1(credentials.NewStaticCredentials("AKID", "SECRET"))
}
