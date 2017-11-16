package signer

type x509RSAProject struct {
	rootCA      RSACert
	projectCert RSACert
}

func (p *x509RSAProject) Sign(input []byte) ([]byte, error) {
	signer := Newx509RSASigner()
	return signer.Sign(input, p.projectCert.GetPrivateKey())
}

func (p *x509RSAProject) SavePrivateKeyTo(uri string) error {
	accessor, err := ParseURI(uri)
	if err != nil {
		return err
	}
	err = accessor.Upload(p.projectCert.GetPrivateKeyBytes())
	if err != nil {
		return err
	}
	return nil
}

func (p *x509RSAProject) SaveCertificateTo(uri string) error {
	accessor, err := ParseURI(uri)
	if err != nil {
		return err
	}
	err = accessor.Upload(p.projectCert.GetCertificateBytes())
	if err != nil {
		return err
	}
	return nil
}
