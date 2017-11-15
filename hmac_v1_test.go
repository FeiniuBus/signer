package signer

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/FeiniuBus/log"
	"github.com/stretchr/testify/assert"
)

type body struct {
	Name string
	Age  int
}

func TestSignPutRequest(t *testing.T) {
	b := body{
		Name: "xqlun",
		Age:  31,
	}
	data, _ := json.Marshal(b)
	req := buildPutRequest(string(data))
	signer := buildSigner()

	res := signer.Sign(req, 10*time.Second)

	if date := res.Header.Get(xFeiniuBusDateHeader); len(date) <= 0 {
		t.Errorf("Can't find signature time")
	}

	for k, v := range res.Header {
		req.Header.Set(k, v[0])
	}

	validator := NewHMACValidatorV1(func(id string) (string, error) {
		return "SECRET", nil
	}, func(v *HMACValidatorV1) {
		v.Logger, _ = log.New(false)
	})

	assert.True(t, validator.Verify(req), "Expect is true")
}

func TestSignGetRequest(t *testing.T) {
	values := url.Values{}
	values.Set("id", "uuid")
	values.Set("type", "Topic")

	req := buildGetRequest(values)
	signer := buildSigner()

	res := signer.Sign(req, 10*time.Second)

	for k, v := range res.Header {
		req.Header.Set(k, v[0])
	}

	validator := NewHMACValidatorV1(func(id string) (string, error) {
		return "SECRET", nil
	}, func(v *HMACValidatorV1) {
		v.Logger, _ = log.New(false)
	})

	assert.True(t, validator.Verify(req), "Expect is true")
}

func buildGetRequest(values url.Values) *Request {
	endpoint := "https://dc.feiniubus.com:5100/fns/v1/topic"
	uri, _ := url.Parse(endpoint)
	uri.RawQuery = values.Encode()
	request, _ := http.NewRequest("GET", uri.String(), nil)
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Accept-Encoding", "gzip")

	req := &Request{
		Method: request.Method,
		URL:    request.URL,
		Body:   nil,
		Header: request.Header,
	}

	return req
}

func buildPutRequest(body string) *Request {
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
	return NewHMACSignerV1("AKID", "SECRET")
}
