package signer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
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

func TestCSharpValidator(t *testing.T) {
	b := `{"name":"config_appsettings","env":"Development","attrs":{"mysql_profile":"mysql","mysql_db":"feiniubus_app_version","mysql_env":"Development","redis_profile":"redis","redis_db":"2","redis_env":"Development","mongo_profile":"mongo","mongo_env":"Development","mongo_db":"system_config"},"lang":"CSharp"}`
	uri, _ := url.Parse("http://172.16.2.117:5100/cc/v1/fetch")

	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Host", "172.16.2.117:5100")
	header.Set("User-Agent", "Polaris-sdk-dotnet-coreclr/.NET_CORE/4.6.00001.0 OS/Darwin_17.2.0_Darwin_Kernel_Version_17.2.0:_Fri_Sep_29_18:27:05_PDT_2017;_root:xnu-4570.20.62~3/RELEASE_X86_64")
	header.Set("Connection", "keep-alive")
	header.Set("Accept-Encoding", "gzip")
	header.Set("X-FeiniuBus-Date", "20171121T104103Z")
	header.Set("Content-Type", "application/json")
	header.Set("Content-Length", "302")
	header.Set("Authorization", "FNBUS1-HMAC-SHA256 Credential=11E7BEAB19F97FF1878AFA163EE05ADE/20171121/feiniubus_request,SignedHeaders=accept;accept-encoding;connection;content-type;host;user-agent,Signature=6b4ec6f5d845aa5b0587ff64d0448fdc41393c8977f471c7a7f14503a8dc12e1")

	req := &Request{
		Body:   bytes.NewReader([]byte(b)),
		URL:    uri,
		Method: "POST",
		Header: header,
	}

	validator := NewHMACValidatorV1(func(id string) (string, error) {
		return "3a57527a8b38f4ddf86609cfba26f86bef045186d59b4994487437947ba733d2", nil
	})

	assert.True(t, validator.Verify(req), "Expect is true")
}

func TestValidator(t *testing.T) {
	b := body{
		Name: "xqlun",
		Age:  31,
	}
	data, _ := json.Marshal(b)
	req := buildPutRequest(string(data))
	req.Header.Set("Host", "dc.feiniubus.com:5100")
	req.Header.Set("X-FeiniuBus-Date", "20171116T093341Z")
	req.Header.Set("Authorization", "FNBUS1-HMAC-SHA256 Credential=AKID/20171116/feiniubus_request,SignedHeaders=accept;content-length;content-type;host,Signature=7ed9bb5b234d1dc2f4cdf6fa293e32603c0b190f90c2a9681e7b22eb8ef2ef4a")

	validator := NewHMACValidatorV1(func(id string) (string, error) {
		return "SECRET", nil
	}, func(v *HMACValidatorV1) {
		v.Logger, _ = log.New(false)
	})

	assert.True(t, validator.Verify(req), "Expect is true")
}

func TestSignGetRequest(t *testing.T) {
	values := url.Values{}
	values.Set("type", "uuid")
	values.Set("id", "Topic")

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
	request.Header.Add("Content-Length", strconv.Itoa(len(body)))
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
