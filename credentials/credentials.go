package credentials

import (
	"sync"
)

// A Value is the credentials value for individual credential fields.
type Value struct {
	// Identifier used to uniquely identify the signature key
	Identifier string

	// Key is the signature key
	Key string
}

// A Provider is the interface for any component which will provide credentials
// Value.
type Provider interface {
	// Retrieve returns credential Value if it successfully retrieved the value.
	// Error is returned if the value were not obtainable, or empty.
	Retrieve() (Value, error)

	// IsExpired returns if the credentials are no longer valid, and need
	// to be retrieved.
	IsExpired() bool
}

// A Credentials provides synchronous safe retrieval of credentials Value.
type Credentials struct {
	creds        Value
	forceRefresh bool
	m            sync.Mutex
	provider     Provider
}

// NewCredentials returns a pointer to a new Credentials with the provider set.
func NewCredentials(provider Provider) *Credentials {
	return &Credentials{
		provider:     provider,
		forceRefresh: true,
	}
}

// Get returns the credentials value, or error if the credentials Value failed
// to be retrieved.
func (c *Credentials) Get() (Value, error) {
	c.m.Lock()
	defer c.m.Unlock()

	if c.isExpired() {
		creds, err := c.provider.Retrieve()
		if err != nil {
			return Value{}, err
		}
		c.creds = creds
		c.forceRefresh = false
	}

	return c.creds, nil
}

// IsExpired returns if the credentials are no longer valid, and need
// to be retrieved.
func (c *Credentials) IsExpired() bool {
	c.m.Lock()
	defer c.m.Unlock()

	return c.isExpired()
}

func (c *Credentials) isExpired() bool {
	return c.forceRefresh || c.provider.IsExpired()
}
