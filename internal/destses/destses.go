package destses

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/psanford/cloudtrail-tattletail/awsstub"
	"github.com/psanford/cloudtrail-tattletail/config"
	"github.com/psanford/cloudtrail-tattletail/internal/destination"
)

type Loader struct {
}

func NewLoader() *Loader {
	return &Loader{}
}

var typeName = "ses"

func (l *Loader) Type() string {
	return typeName
}

func (l *Loader) Load(c config.Destination) (destination.Destination, error) {
	if c.ID == "" {
		return nil, fmt.Errorf("(ses) destination.id must be set")
	}
	if len(c.ToEmails) == 0 {
		return nil, fmt.Errorf("(ses) destination.to_emails must be set for %q", c.ID)
	}

	if c.FromEmail == "" {
		return nil, fmt.Errorf("(ses) destination.from_email must be set for %q", c.ID)
	}

	d := DestSES{
		id:        c.ID,
		fromEmail: c.FromEmail,
	}

	for _, email := range c.ToEmails {
		email := email
		d.toEmails = append(d.toEmails, &email)
	}

	return &d, nil
}

type DestSES struct {
	id        string
	toEmails  []*string
	fromEmail string
}

func (d *DestSES) ID() string {
	return d.id
}

func (d *DestSES) Type() string {
	return typeName
}

func (d *DestSES) Send(name, desc string, rec map[string]interface{}, matchObj interface{}) error {

	jsonObj, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal obj err: %w", err)
	}

	var matchText string
	m, ok := matchObj.(map[string]interface{})
	if !ok || !reflect.DeepEqual(rec, m) {
		b, err := json.MarshalIndent(matchObj, "", "  ")
		if err == nil {
			matchText = string(b)
		}
	}

	body := fmt.Sprintf("Alert: %s\n\n%s\n\n\nevent:\n%s\n", name, desc, jsonObj)
	if matchText != "" {
		body += "match: " + matchText + "\n"
	}

	_, err = awsstub.SendEmail(&ses.SendEmailInput{
		Source: &d.fromEmail,
		Destination: &ses.Destination{
			ToAddresses: d.toEmails,
		},
		Message: &ses.Message{
			Subject: &ses.Content{
				Data: aws.String("Cloudtrail Tattletail event"),
			},
			Body: &ses.Body{
				Text: &ses.Content{
					Data: &body,
				},
			},
		},
	})
	return err
}
