package signer

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type RSACertS3Accessor struct {
	Region  string
	Bucket  string
	Key     string
	Profile string
}

//ParseS3URI sample : s3://default/sampleBucket/sampleKey?Profile=Profile1 .
func ParseS3URI(uri string) (RSACertAccessor, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "s3" {
		return nil, fmt.Errorf("'s3://' is expected, but the '%s://' is provided", u.Scheme)
	}
	if strings.Index("/", u.Path) == -1 || len(strings.Split("/", u.Path)) != 2 {
		return nil, fmt.Errorf("path '%s' format is incorrect, should be '{Bucket}/{Key}'", u.Path)
	}
	path := strings.Split("/", u.Path)
	r := &RSACertS3Accessor{
		Region: u.Host,
		Bucket: path[0],
		Key:    path[1],
	}
	if u.RawQuery != "" {
		m, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return nil, err
		}
		profile, ok := m["Profile"]
		if ok {
			r.Profile = profile[0]
		}
	}
	return r, nil
}

func (u *RSACertS3Accessor) Session() *session.Session {
	var sess *session.Session
	if u.Profile == "" {
		sess = session.Must(session.NewSession())
	} else {
		sess = session.Must(session.NewSessionWithOptions(session.Options{
			Profile: u.Profile,
		}))
	}
	return sess
}

func (u *RSACertS3Accessor) Upload(body []byte) error {
	sess := u.Session()
	uploader := s3manager.NewUploader(sess)
	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(u.Bucket),
		Key:    aws.String(u.Key),
		Body:   bytes.NewReader(body),
	})
	if err != nil {
		return err
	}
	return nil
}

func (u *RSACertS3Accessor) Download() ([]byte, error) {
	sess := u.Session()
	downloader := s3manager.NewDownloader(sess)
	buffer := new(aws.WriteAtBuffer)
	_, err := downloader.Download(buffer, &s3.GetObjectInput{
		Bucket: aws.String(u.Bucket),
		Key:    aws.String(u.Key),
	})
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
