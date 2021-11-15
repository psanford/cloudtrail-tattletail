package destslack

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/psanford/cloudtrail-tattletail/config"
	"github.com/psanford/cloudtrail-tattletail/internal/destination"
	"github.com/slack-go/slack"
)

type Loader struct {
}

func NewLoader() *Loader {
	return &Loader{}
}

var typeName = "slack_webhook"

func (l *Loader) Type() string {
	return typeName
}

func (l *Loader) Load(c config.Destination) (destination.Destination, error) {
	if c.ID == "" {
		return nil, fmt.Errorf("(slack_webhook) destination.id must be set")
	}
	if c.WebhookURL == "" {
		return nil, fmt.Errorf("(slack_webhook) destination.webhook_url must be set for %q", c.ID)
	}

	d := DestSlackWebhook{
		id:         c.ID,
		webhookURL: c.WebhookURL,
	}
	return &d, nil
}

type DestSlackWebhook struct {
	id         string
	webhookURL string
}

func (d *DestSlackWebhook) ID() string {
	return d.id
}

func (d *DestSlackWebhook) Type() string {
	return typeName
}

func (d *DestSlackWebhook) Send(name, desc string, rec map[string]interface{}, matchObj interface{}) error {

	jsonObj, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal obj err: %w", err)
	}

	var matchTxt string

	m, ok := matchObj.(map[string]interface{})
	if !ok || !reflect.DeepEqual(rec, m) {
		b, err := json.MarshalIndent(matchObj, "", "  ")
		if err == nil {
			matchTxt = string(b)
		}
	}

	msg := slack.WebhookMessage{
		IconEmoji: "red_circle",
		Username:  "Cloudtrail Tattletail",
		Attachments: []slack.Attachment{
			{
				Color: "danger",
				Title: "Cloudtrail Tattletail Event",
				Text:  string(jsonObj),
				Fields: []slack.AttachmentField{
					{
						Title: "Alert Name",
						Value: name,
						Short: true,
					},
					{
						Title: "Description",
						Value: desc,
						Short: true,
					},
				},
			},
		},
	}

	if matchTxt != "" {
		msg.Attachments[0].Fields = append(msg.Attachments[0].Fields, slack.AttachmentField{
			Title: "Match",
			Value: matchTxt,
		})
	}

	return slack.PostWebhook(d.webhookURL, &msg)
}

func (d *DestSlackWebhook) String() string {
	paths := strings.Split(d.webhookURL, "/")
	if len(paths) > 4 {
		paths[len(paths)-1] = "**FILTERED**"
	}

	return fmt.Sprintf("{id: %s webhookURL: %s}", d.id, strings.Join(paths, "/"))
}
