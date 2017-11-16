package signer

import (
	"testing"
)

func TestRSAWorkbench(t *testing.T) {
	root, err := Parsex509RSACert(getRootCA(), getRootKey())
	if err != nil {
		t.Fatal(err)
	}

	workbench := Newx509RSAWorkbench(root)
	p, err := workbench.GenerateRSAPrivateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	project, err := workbench.CreateProject(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = project.Sign([]byte("testing"))
	if err != nil {
		t.Fatal(err)
	}
}
