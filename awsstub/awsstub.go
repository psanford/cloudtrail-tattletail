package awsstub

import (
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/service/sns"
)

var (
	S3GetObj            func(*s3.GetObjectInput) (*s3.GetObjectOutput, error)
	S3GetObjWithContext func(aws.Context, *s3.GetObjectInput, ...request.Option) (*s3.GetObjectOutput, error)

	SnsPublish func(*sns.PublishInput) (*sns.PublishOutput, error)

	SendEmail func(*ses.SendEmailInput) (*ses.SendEmailOutput, error)
)

func InitAWS() {
	awsSession := session.New(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION")),
	})

	s3Client := s3.New(awsSession)
	snsClient := sns.New(awsSession)
	sesClient := ses.New(awsSession)

	S3GetObj = s3Client.GetObject
	S3GetObjWithContext = s3Client.GetObjectWithContext
	SnsPublish = snsClient.Publish

	SendEmail = sesClient.SendEmail

}
