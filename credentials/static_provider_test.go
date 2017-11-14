package credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaticProviderGet(t *testing.T) {
	s := StaticProvider{
		Value: Value{
			Identifier: "AKID",
			Key:        "SECRET",
		},
	}

	creds, err := s.Retrieve()
	assert.Nil(t, err, "Expect no error")
	assert.Equal(t, "AKID", creds.Identifier, "Expect access key ID to match")
	assert.Equal(t, "SECRET", creds.Key, "Expect secret access key to match")
}
