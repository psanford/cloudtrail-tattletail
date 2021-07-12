package awsstub

import (
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sns"
)

var (
	S3GetObj func(*s3.GetObjectInput) (*s3.GetObjectOutput, error)

	SnsPublish func(*sns.PublishInput) (*sns.PublishOutput, error)
)

func InitAWS() {
	awsSession := session.New(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION")),
	})

	s3Client := s3.New(awsSession)
	snsClient := sns.New(awsSession)

	S3GetObj = s3Client.GetObject
	SnsPublish = snsClient.Publish
}
