package destsns

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/psanford/cloudtrail-tattletail/config"
	"github.com/psanford/cloudtrail-tattletail/internal/destination"
)

type Loader struct {
}

var (
	snsPublish func(*sns.PublishInput) (*sns.PublishOutput, error)
)

func NewLoader() *Loader {
	awsSession := session.New(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION")),
	})
	snsClient := sns.New(awsSession)

	snsPublish = snsClient.Publish

	return &Loader{}
}

func (l *Loader) Type() string {
	return "sns"
}

func (l *Loader) Load(c config.Destination) (destination.Destination, error) {
	if c.ID == "" {
		return nil, fmt.Errorf("(sns) destination.id must be set")
	}
	if c.SNSARN == "" {
		return nil, fmt.Errorf("(sns) destination.sns_arn must be set for %q", c.ID)
	}

	if !strings.HasPrefix(c.SNSARN, "arn:") {
		return nil, fmt.Errorf("(sns) destination.sns_arn must be a full ARN beginning with `arn:` for %q", c.ID)
	}

	d := DestSNS{
		id:  c.ID,
		arn: c.SNSARN,
	}
	return &d, nil
}

type DestSNS struct {
	id  string
	arn string
}

func (d *DestSNS) ID() string {
	return d.id
}

func (d *DestSNS) Type() string {
	return "sns"
}

func (d *DestSNS) Send(name, desc string, rec map[string]interface{}, matchObj interface{}) error {
	payload := Payload{
		Name:   name,
		Desc:   desc,
		Record: rec,
		Match:  matchObj,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = snsPublish(&sns.PublishInput{
		Message:  aws.String(string(payloadBytes)),
		TopicArn: &d.arn,
	})

	if err != nil {
		return fmt.Errorf("sns publish failure topic_arn=%q err=%w", d.arn, err)
	}

	return nil
}

type Payload struct {
	Name   string                 `json:"name"`
	Desc   string                 `json:"description"`
	Record map[string]interface{} `json:"record"`
	Match  interface{}            `json:"match"`
}
