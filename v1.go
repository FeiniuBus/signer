package signer

import (
	"time"

	"github.com/FeiniuBus/signer/credentials"
)

type HMACSignerV1 struct {
	Credentials *credentials.Credentials

	// currentTimeFn returns the time value which represents the current time.
	currentTimeFn func() time.Time
}

// NewHMACSignerV1 returns a HMACSigner pointer
func NewHMACSignerV1(creds *credentials.Credentials, options ...func(*HMACSignerV1)) *HMACSignerV1 {
	v1 := &HMACSignerV1{
		Credentials: creds,
	}

	for _, option := range options {
		option(v1)
	}

	return v1
}

func (v1 *HMACSignerV1) Sign(r *Request, signTime time.Time, exp time.Duration) (*SigningResult, error) {
	return nil, nil
}
