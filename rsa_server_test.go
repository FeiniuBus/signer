package signer

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var store RSAStore

func Test_RSAServer(t *testing.T) {

	root, err := Parsex509RSACert(getRootCA(), getRootKey())
	if err != nil {
		t.Fatal(err)
	}

	factory := NewRSAStoreFactory("test", "polaris/Certificates", root, GetDefaultSubject())
	store, err := factory.Create(X509RSAStore_Test)
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

func Test_RSAServerParallel(t *testing.T) {

	root, err := Parsex509RSACert(getRootCA(), getRootKey())
	if err != nil {
		t.Fatal(err)
	}

	factory := NewRSAStoreFactory("test", "polaris/Certificates", root, GetDefaultSubject())
	store, err := factory.Create(X509RSAStore_Test)
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

type ChargeResult struct {
	ProviderId              string `json:"provider_id"`
	Message                 string `json:"message"`
	ProviderPrivilege       int    `json:"provider_privilege"`
	DiscountAmt             int    `json:"discount_amt"`
	Timestamp               string `json:"timestamp"`
	Signature               string `json:"signature"`
	SignatureCertificateURL string `json:"signature_certificate_url"`

	Metadata map[string]interface{} `json:"metadata"`
	Amount   int                    `json:"amount"`
	OrderId  string                 `json:"order_id"`
	Result   bool                   `json:"result"`
}

func getSignString(r *ChargeResult) string {
	return strings.Join([]string{
		"provider_id",
		r.ProviderId,
		"message",
		r.Message,
		"provider_privilege",
		strconv.Itoa(r.ProviderPrivilege),
		"discount_amt",
		strconv.Itoa(r.DiscountAmt),
		"timestamp",
		r.Timestamp,
		"amount",
		strconv.Itoa(r.Amount),
		"order_id",
		r.OrderId,
		"result",
		strconv.FormatBool(r.Result),
	}, "\n")
}

func Test_Payload(t *testing.T) {
	body := `{"provider_id":"2017112221001104000269064675","message":"","provider_privilege":0,"discount_amt":0,"timestamp":"2017-11-22T13:00:24Z","signature":"69fabe51753e2d7c4d9fa09ee19adb7e18d0393e4ac28695f2e576e8a16e1ae0d294a40ebf0699b87afa851b3808d51fda41a018e539a55d2ea2f75eec5d78b0e0ae1312399aef4dd382763a6dd2c96bb5eeed3612f83b61a0d69c4c6a4d02989522d80db8befefa2224f7df95871457aa89a405a33ad9c0ca76d8e054842321a5294027b8c02f097ff7e5772ea2aaee90619af39244c5acb088468964496981bceecb3f75dd3a193928a1a6543eef02128e5c58edfd801e7f4bab0abc0d888ae42d4660df9a228ab76cc809b953992c8cb7d08646638c0508e55acf4342c2396e3ae964850ecc70833a34f9463f0d91744b887f446a4a89fe5eea7b606b792f","signature_certificate_url":"https://s3.cn-north-1.amazonaws.com.cn/polaris/Certificates/dev_1511167477_11E7BED438B318B1878AFA163EE05ADE.crt","metadata":{"cars":[{"ferry_car_type_id":"59113da2e07a662be7ff0ea2","number":1,"price":200,"seats":7}],"charge_id":"137306146032082539","order_type":"PassengerDedicated","terminal":"PG","user_id":"78680843347991134","user_name":"18780156572"},"amount":198,"order_id":"137306145992729955","result":true}`
	var r ChargeResult
	err := json.Unmarshal([]byte(body), &r)
	if err != nil {
		t.Fatal(err)
	}
	s := getSignString(&r)
	//s := "test"
	fmt.Print([]byte(s))
	fmt.Println()
	s64 := base64.StdEncoding.EncodeToString([]byte(s))
	fmt.Print(s64)
	fmt.Println()
	pk, err := ParseRsaPrivateKey(PayloadTestKey())
	if err != nil {
		t.Fatal(err)
	}
	signer := Newx509RSASigner()
	sign, err := signer.Sign([]byte(s), pk)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Print(sign)
	fmt.Println()
	hexStr := hex.EncodeToString(sign)
	fmt.Print(hexStr)
	fmt.Println()
	b64Str := base64.StdEncoding.EncodeToString(sign)
	fmt.Print(b64Str)
	fmt.Println()
	fmt.Print(sign)
	cert, err := ParseX509Certificate(PayloadTestCert())
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := Verfy([]byte(s), sign, cert); !ok {
		t.Fail()
	}
}

func Verfy(bytes []byte, signature []byte, certificate *x509.Certificate) (bool, error) {
	err := certificate.CheckSignature(x509.SHA256WithRSA, bytes, signature)
	if err != nil {
		return false, err
	}
	return true, err
}

const newLine string = "\n"

//test_1510908475_test_client.pem
func PayloadTestKey() []byte {
	s := "-----BEGIN PRIVATE KEY-----" + newLine
	s += "MIIEowIBAAKCAQEAyIN1TMduiyUWDHvNzAetsyQkJMG5e3chQQZJvip3JSTuAc9J" + newLine
	s += "iNG2BlExCSAfhFPoH4mD1I2XYuRsOJF+PEfj9YMfcaYchWsD7a+Uu03Kau5qU4Mu" + newLine
	s += "SB8cqL9fNh13RA3ak/qs13LdQxtglmhFzmZr44zJ8DJbmeOGEP5+027yMiQJcDBf" + newLine
	s += "N9dsJqt+SMV8TPFjq4YQfTbFjQ1FQaKMaW5lyeGl+aYGH5rW/mUnfgfRFRKU+hdV" + newLine
	s += "G24TLL2QnIWEX0a1SdLXzPnU1HxyfFOH1QC1bq3hQbRfnpVWFKMDVzSe/Lug8dNS" + newLine
	s += "A1vsxmcoLwWjYnCNT8jA2UbHMqRaT6+BY/ROmQIDAQABAoIBAAZblLaQhELJND/F" + newLine
	s += "FSto+ur5NGQt+FGf32AOcPwkoI5+80T/a5d4/sqIfIOLjzRE7NFDLPjqXGh4Ua4h" + newLine
	s += "ft0ucl3wgGi8GZ9pW0CIFrExsD9fu+NV/3ut8Nyw5LX0jTmNLucORbi3HajpD1D1" + newLine
	s += "kXEP8k/OwQBquFjSzAdx6leN5wQL7gtMR8B/nPL5tm1q9hQRi0Xdd5Bjg6v7U2iX" + newLine
	s += "MO2h557nQ+udYshVKPEGCTtJrRgr3zJld6HWOXgr4G4ArqVF6SaAUfTCevoTZQCI" + newLine
	s += "NUGVUxWuTEhxff+AYsFVgl7mIAgkNBJVQYGNbmIN5e/0C6mRsBu1+BjpZkBpOYo5" + newLine
	s += "Jd4SlDkCgYEA+ChiCmgXM3KilVZ9S+sodGeSuQK9Qj/kzbY6z6p6Ux+E6XOh2aIR" + newLine
	s += "RKLa+o0Hct1Bl4euDyxTtDTcjpI+kVezLBwi5g1Z5tbQlfIzLimtSqyzMQ3GNHAq" + newLine
	s += "i/Sbr7oGx/z+zs84TTx0QsOdLYsyhzwNCrbT7on7IlmVQNvdwaheZEsCgYEAztmh" + newLine
	s += "HMjuHkRWmLrrXJr+e4jZS2xMK2bn/NotJ9MOCTP8S9CDBB3x4ml2reMXe0+Y5Ake" + newLine
	s += "3BJaw7F94oRZmF0BX7vrg7moVuKFyNZbwav+VHVtgsaPgBBPaJbBomijAdaPtICQ" + newLine
	s += "MoGNvUryY1/Sqh5Wfb5l8ELKo2SUpjWk5QimoisCgYEAukFtHIx15XqEBvxsfJ/a" + newLine
	s += "tEvMtyoULPZR4AiHabh1qY/9rU7JytQ2i8KEAwv47ECe64G9pcvKY3ZNmICxj1s4" + newLine
	s += "ssHHe83HjVfsJK8ttNc5JtQqhoXlHxSVCoikladVUaNVCJpFksruI/I4NafFW/U5" + newLine
	s += "gLIqrV5I7MY6HP0pGyIo/rMCgYBzXqzeyi8NkJ4gF3k4sHYp3r0btS6SspXH0MSI" + newLine
	s += "xs24Uldwzb6VaEJGPv5jpBqvu0iSP4gHxPD83x1QXvM96PngNIb6dG2w8C0gRHbv" + newLine
	s += "AYgcAVbwLuFQ00gHFLaxZ90rJEoIqgBDO0EcCBZDWOm92qfxAGYI6KfvFCVYwujS" + newLine
	s += "mc2e+wKBgBxTrPKpTYO92Uu29XLOgwwB7anJ635YT24IBp47frLA97y2gCB7LOfJ" + newLine
	s += "SDddlkYTUwSrC8V61iVw8iw/E4WK6qUgm4lq8rosie9WXjIDRNoa2M6VEPjZ2k8l" + newLine
	s += "yoaHcPMmQRu53WDkyHQ5XEquCw2lMwZb6rPDboMxAohdfyBLA1A8" + newLine
	s += "-----END PRIVATE KEY-----"
	return []byte(s)
}

//test_1510908475_test_client.crt
func PayloadTestCert() []byte {
	s := "-----BEGIN CERTIFICATE-----" + newLine
	s += "MIIDvjCCAqagAwIBAgIITWWCIQf8/VIwDQYJKoZIhvcNAQELBQAwbjELMAkGA1UE" + newLine
	s += "BhMCQ04xEDAOBgNVBAgMB1NJQ0hVQU4xEDAOBgNVBAcMB0NIRU5HRFUxEjAQBgNV" + newLine
	s += "BAoMCUZFSU5JVUJVUzEQMA4GA1UECwwHQ0lUQURFTDEVMBMGA1UEAwwMQ0lUQURF" + newLine
	s += "TCBBVVRIMB4XDTE3MTExNzA4NDc1NVoXDTE3MTIxNzA4NDc1NVowbjELMAkGA1UE" + newLine
	s += "BhMCQ04xEDAOBgNVBAgTB1NJQ0hVQU4xEDAOBgNVBAcTB0NIRU5HRFUxEjAQBgNV" + newLine
	s += "BAoTCUZFSU5JVUJVUzEQMA4GA1UECxMHQ0lUQURFTDEVMBMGA1UEAxMMQ0lUQURF" + newLine
	s += "TCBBVVRIMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyIN1TMduiyUW" + newLine
	s += "DHvNzAetsyQkJMG5e3chQQZJvip3JSTuAc9JiNG2BlExCSAfhFPoH4mD1I2XYuRs" + newLine
	s += "OJF+PEfj9YMfcaYchWsD7a+Uu03Kau5qU4MuSB8cqL9fNh13RA3ak/qs13LdQxtg" + newLine
	s += "lmhFzmZr44zJ8DJbmeOGEP5+027yMiQJcDBfN9dsJqt+SMV8TPFjq4YQfTbFjQ1F" + newLine
	s += "QaKMaW5lyeGl+aYGH5rW/mUnfgfRFRKU+hdVG24TLL2QnIWEX0a1SdLXzPnU1Hxy" + newLine
	s += "fFOH1QC1bq3hQbRfnpVWFKMDVzSe/Lug8dNSA1vsxmcoLwWjYnCNT8jA2UbHMqRa" + newLine
	s += "T6+BY/ROmQIDAQABo2AwXjAOBgNVHQ8BAf8EBAMCBJAwHQYDVR0lBBYwFAYIKwYB" + newLine
	s += "BQUHAwIGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUyQClQDQD" + newLine
	s += "EjmH4MxQfQpgc3oxA6MwDQYJKoZIhvcNAQELBQADggEBAGeLOUwLngZN0Gmj5eo/" + newLine
	s += "srN2t9xydjDxKpEwnsyHuvQJUmQrNL6uFJflT1AzNAGbOl/BEZ42TXYi9NsZtRc0" + newLine
	s += "4Rp+J1EC8tSdGiWWYUFWYoHn82CDfsFMPZ96eSkbQbfrJfe0gJutwJlzixVUSF0q" + newLine
	s += "Ve9vMq6Yh07ZcOdlaN8e7K/5kcCwIZ496SQy1RUaNYFw9RtGzbq8D/Wqbx9xak8X" + newLine
	s += "aqV35XcVcmxfQWyMAPMUcDiA1o2NReCqz2on5J6G9Q9vnoYKmVSILhhqE/SDb16c" + newLine
	s += "PrLq27Hwobqe1RcFSgxVtuYMlibz2gW0A21JBqpeaqdOYiDoGEbfi1CgL+RjOcQ+" + newLine
	s += "k24=" + newLine
	s += "-----END CERTIFICATE-----"
	return []byte(s)
}
