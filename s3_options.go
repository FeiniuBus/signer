package signer

var s3options *S3Options

type S3Options struct {
	id     string
	secret string
	region string
}

func InitS3Options(id string, secret string, region string) {
	s3options = &S3Options{
		id:     id,
		secret: secret,
		region: region,
	}
}

func GetS3Options() *S3Options {
	return s3options
}

func (s *S3Options) GetAppId() string {
	return s.id
}

func (s *S3Options) GetAppSecret() string {
	return s.secret
}

func (s *S3Options) GetRegion() string {
	return s.region
}
