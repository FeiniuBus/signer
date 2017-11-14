package signer

import (
	"io"
	"net/http"
	"time"
)

// A Request is an abstract representation of a http request.
type Request struct {
	Body  io.ReadSeeker
	Query http.Header
	Path  string
	Host  string
}

// SigningResult is a signing result strcuture
type SigningResult struct {
	Signature string
	Timestamp string
}

// A Signer is the interface for any component which will provide signature algorithm.
type Signer interface {
	Sign(r *Request, signTime time.Time, exp time.Duration) (*SigningResult, error)
}
