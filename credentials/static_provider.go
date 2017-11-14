package credentials

import "errors"

var (
	ErrStaticCredentialsEmpty = errors.New("static credentials are empty")
)

// A StaticProvider is a set of credentials which are set programmatically,
// and will never expire.
type StaticProvider struct {
	Value
}

func NewStaticCredentials(id, key string) *Credentials {
	return NewCredentials(&StaticProvider{Value: Value{
		Identifier: id,
		Key:        key,
	}})
}

func (s *StaticProvider) Retrieve() (Value, error) {
	if s.Identifier == "" || s.Key == "" {
		return Value{}, ErrStaticCredentialsEmpty
	}

	return s.Value, nil
}

func (s *StaticProvider) IsExpired() bool {
	return false
}
