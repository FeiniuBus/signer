[![Build Status](https://travis-ci.org/FeiniuBus/signer.svg?branch=master)](https://travis-ci.org/FeiniuBus/signer)

[中文版本](https://github.com/FeiniuBus/signer/blob/master/README.zhcn.md)

# signer

A high-performance Go(golang) signature algorithm package. Used to sign HTTP requests.

# X509 RSA Signature Server
This is a signature server using RSA private key and x509 certifacate

## How to use ?
* BEFORE ALL : Initialize S3 Options
```
    signer.InitS3Options(APIKEY, APUSECRET, REGION)
```

* Step 1 : Parse your root private key and certificate
```
    root, err := Parsex509RSACert(**root certificate bytes (asn1)**, **root private key bytes (asn1)**)
```

* Step 2 : Create a store instance as private key storage
** The Store Should Be Singleton, IT'S THREAD SAFE **
```
factory := NewRSAStoreFactory(** Tag (eg. dev) **, ** AWS S3 Bucket **, **Root cert from Step 1**, **x509 Subject (*signer.x509Subject)**)
store, err := factory.Create(x509RSAStore_OneToMany) //x509RSAStore_OneToMany: One private key to many client certificate 
```

* Step 3 : Create RSA Server and Client
```
server := Newx509RSAServer(**RSA Store from Step 2**)
client, err := server.CreateClient(**Client Identity SHOULD BE UNIQUEU**)
```

* Step 4 : Sign
```
signature, key, err := client.Sign([]byte("testing"))
//signature: the bytes value client should use x509 certificate to verfy
//key: key of x509 certificate uploaded to AWS S3 Service
```

* `new` Sign string array data as default encoding
signature, key, err := client.ASN1Sign("Type Lable","section1","section2","section3","section4")
//Arguments[0]: separator
//Arguments[...]: strings need sign later, client will encode them to default(utf8) encoding. 

* `new` Sign string array data as ASN.1 encoding
```
signature, key, err := client.StringsSign("\r\n","section1","section2","section3","section4")
//Arguments[0]: Type of ASN.1 Declaration, eg. 'SAMPLE MESSAGE'
//Arguments[...]: strings need sign later, client will encode them to ASN.1 encoding. 

```

## How to verfy ?
We are using openssl signature, almost supported by any program launguage.

* Here is the parameters you may need :
* Root RSA Keysize : 2048
* Root RSA Key Encoding : ASN.1
* Root Certificate Format : x.509
* Root Certificate Encoding : ASN.1
* RSA Keysize : 2048
* RSA Key Encoding : ASN.1
* Client Certificate Format : x.509
* Client Certificate Encoding : ASN.1

* Here is the parameters of ASN1Sign :
* Separator: \r\n
* ASN.1 Declaration Type Auto Turn Upper : enabled
* Single line max length : 64 letters

## How to get root certificates ?
* Run in bash
```bash
openssl genrsa -out rsakey.pem 2048 && \
openssl rsa -in rsakey.pem -pubout -out rsakey.pub && \
openssl req -x509 -new -days 365 -key rsakey.pem -out rootcert.crt
```