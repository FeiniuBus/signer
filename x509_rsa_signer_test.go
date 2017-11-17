package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func Testx509RSASigner(t *testing.T) {
	root, err := Parsex509RSACert(getRootCA(), getRootKey())
	if err != nil {
		t.Fatal(err)
	}

	priKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	issuor := Newx509RSACertIssuor(root, priKey)

	subject := GetDefaultSubject()
	cert, err := issuor.Issue(subject)
	if err != nil {
		t.Fatal(err)
	}

	signer := Newx509RSASigner()
	content := []byte("Citadel Unit Testing")
	_, err = signer.Sign(content, cert.GetPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
}

func getRootCA() []byte {
	ca := "-----BEGIN CERTIFICATE-----\r\n"
	ca += "MIIDrzCCApegAwIBAgIJANtlu9KZ/MlAMA0GCSqGSIb3DQEBCwUAMG4xCzAJBgNV\r\n"
	ca += "BAYTAkNOMRAwDgYDVQQIDAdTSUNIVUFOMRAwDgYDVQQHDAdDSEVOR0RVMRIwEAYD\r\n"
	ca += "VQQKDAlGRUlOSVVCVVMxEDAOBgNVBAsMB0NJVEFERUwxFTATBgNVBAMMDENJVEFE\r\n"
	ca += "RUwgQVVUSDAeFw0xNzEwMzEwMjM4NTJaFw0xODEwMzEwMjM4NTJaMG4xCzAJBgNV\r\n"
	ca += "BAYTAkNOMRAwDgYDVQQIDAdTSUNIVUFOMRAwDgYDVQQHDAdDSEVOR0RVMRIwEAYD\r\n"
	ca += "VQQKDAlGRUlOSVVCVVMxEDAOBgNVBAsMB0NJVEFERUwxFTATBgNVBAMMDENJVEFE\r\n"
	ca += "RUwgQVVUSDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMqMNS6kz6QI\r\n"
	ca += "yB4qwXGahWsP9DuHTiwp1EXVGKq/5pl2WEq4NSBypvL7Hg4KCUtSH6veHVqXAZDy\r\n"
	ca += "RqC7dhe9Rw3az34oD/q4msoqAGqdQF6hv0pT7sFc3UKhyzzZclPsaIsFl9HsfLl5\r\n"
	ca += "85Fm9osnAsd0Vgw6F5gF4aQHLTnXfytjEtMqR+4u4usSIgqKarrMRUGNZCfmOe+G\r\n"
	ca += "fS9nU1ns5BeU7X75DMheO21G9HcA+HhmEqbQekrar0y67tizDGYsnil4rtNWNWFX\r\n"
	ca += "VtiWf/agoAfBaKY+j4doPAFvWKs2WsGjCfkCFuuzqfMM99HhiTUHoH+ioeR1HiIk\r\n"
	ca += "zYXBQdj7ixUCAwEAAaNQME4wHQYDVR0OBBYEFMkApUA0AxI5h+DMUH0KYHN6MQOj\r\n"
	ca += "MB8GA1UdIwQYMBaAFMkApUA0AxI5h+DMUH0KYHN6MQOjMAwGA1UdEwQFMAMBAf8w\r\n"
	ca += "DQYJKoZIhvcNAQELBQADggEBADY9pw9aHmLeFyV4RSu4BFBhcjswNLp7isTZOuJ/\r\n"
	ca += "OBgTI7Zd5iWxwP4X6pXajB3ULe000poesK8T5SJOi091u3Rh3NVBlUMF6BgYjqM0\r\n"
	ca += "3jUQFfWF6p50OagkzJdkoA7Jx4A08XU6FjoA6YJvDESiGLuoDkcqvaE50LtZUBN4\r\n"
	ca += "HS0s1SBTl7shW1ikpRh3IqS388XjaeZczoT6J8mKyXOq0UCtNAQkBJBif9RHEgcT\r\n"
	ca += "PxrSBRI7fCt4oG26wjveQsPYvw/eeusKiC4w8f+JgzB4KKOA3dQ3deMwJP2BRWgP\r\n"
	ca += "cinoH3GZjypLpGJYDaRkDiViDOBkPBvpQmmKj8ksadPdErQ=\r\n"
	ca += "-----END CERTIFICATE-----"
	return []byte(ca)
}

func getRootKey() []byte {
	key := "-----BEGIN RSA PRIVATE KEY-----\r\n"
	key += "MIIEpQIBAAKCAQEAyow1LqTPpAjIHirBcZqFaw/0O4dOLCnURdUYqr/mmXZYSrg1\r\n"
	key += "IHKm8vseDgoJS1Ifq94dWpcBkPJGoLt2F71HDdrPfigP+riayioAap1AXqG/SlPu\r\n"
	key += "wVzdQqHLPNlyU+xoiwWX0ex8uXnzkWb2iycCx3RWDDoXmAXhpActOdd/K2MS0ypH\r\n"
	key += "7i7i6xIiCopqusxFQY1kJ+Y574Z9L2dTWezkF5TtfvkMyF47bUb0dwD4eGYSptB6\r\n"
	key += "StqvTLru2LMMZiyeKXiu01Y1YVdW2JZ/9qCgB8Fopj6Ph2g8AW9YqzZawaMJ+QIW\r\n"
	key += "67Op8wz30eGJNQegf6Kh5HUeIiTNhcFB2PuLFQIDAQABAoIBAQCof6teek0isQuJ\r\n"
	key += "zRfQYjPLtSIAw7cMll+5GGXE5o/36rPYtRW9QKQST0XZeA/zUQZ3+/d/fVAYPPT0\r\n"
	key += "kf7UEOojZHxo/vsMILbkp7xg9SCvmO+B7gEZax/GZsKkhGDP4EO4I5cBVDMOOZ2e\r\n"
	key += "wIEpkfKF6woKcele1sW3pyDAlb19YRrfNy6yOk4KKjc/PzioaLXyGp+vn29U46uq\r\n"
	key += "O/CJhRDqPTcxzVbE3BUClYnQBmZNnompvBhsdW1o9hLW42Tu+iI5Wqcl+NJdJclk\r\n"
	key += "2uGDII96CKVfqkvYgI/wtUJKFBY5BoJ4vC1Eaa3kewO6STSEmkWPC71pnW3J5io1\r\n"
	key += "QMLSOmWhAoGBAO8IguLcpQtb1Um+26YP3IE5oivrksSo4s/85XLkSjC06lR5FHG2\r\n"
	key += "cf9+Q3apApDhhMixIh6Eif1bK9dm5H/bOzIIGDsnhY/PXKrwOAGov95EeB3NfHpr\r\n"
	key += "faWi8gBmLgZa+jMNxqvQaJ+xLl6JZTrSf4ISEzzUPHln0oFbsKjNoXh3AoGBANjs\r\n"
	key += "twgD731PMIRobS584F9FQiwhIjdjLI7RVKLw+FXt0B4eGcGjW6QHwaiGzwGoqaji\r\n"
	key += "FUY10Nr4pGkCvOA5gh0xDkJPEbTUsUcl6rDMwpSi1IuuWYZaGhqgbY3DoapS6oXb\r\n"
	key += "3+vfuKQ92IzJdTZRCFC4YcVaUnPvYZEdutaitgfTAoGBAKFRCCwcppH83vvO/6OZ\r\n"
	key += "zsGzaJvldv6bz754OU2JffxTDFYIBOEdNOAtkVASjbXDTP64dINOBWZj0jmjqhAT\r\n"
	key += "n2aLifbaHExKsIp4ZgPQo/RYFwxd8mUYCArx5gqY6vTFD1fHM04e74zeYaHRbez9\r\n"
	key += "xKm+kxcZUNrKU4mTnKy/YfrPAoGBAMDI/5F8DeeL7U5/kCj0imOhJcIaYFJhLURv\r\n"
	key += "/YwiJFIZ3BAoKDPTfqo0yoN/65FJ2B5jbwzK3yb8OwGokTulYGGZK1b69n2DWVol\r\n"
	key += "9IHUOEnovIS3GpEwmmp3kWWgK5k3v33ffw4d8fblkALvN+Bh+8XhV+MQ9p5abJeP\r\n"
	key += "mHEQgj5JAoGACIHWJrONz3rQNpm5vJO91nkhhjliMPDi/HUnuoGH+M2k6Al2oc4W\r\n"
	key += "q7Q4N/12JszHyATAOgWOQbnYuuSzmy6/mjZMDfJ51GcXvw0cKnGPfUMAUpBNyTTd\r\n"
	key += "6pNga+4L9GuHGbqkiSgXcB4EPfYm+uadC02qhT+ZQOYExHlcgSKIx7Y=\r\n"
	key += "-----END RSA PRIVATE KEY-----"
	return []byte(key)
}
