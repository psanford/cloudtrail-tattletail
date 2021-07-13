package destslack

import (
	"encoding/json"
	"fmt"
	"reflect"

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

	nameSec := textSec("*Alert Name*", name)
	descSec := textSec("*Description*", desc)

	jsonObj, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal obj err: %w", err)
	}

	recSec := codeSec("*Cloudtrail Record*", string(jsonObj))

	var matchSec *slack.SectionBlock

	m, ok := matchObj.(map[string]interface{})
	if !ok || !reflect.DeepEqual(rec, m) {
		b, err := json.MarshalIndent(matchObj, "", "  ")
		if err == nil {
			matchSec = codeSec("*Match*", string(b))
		}
	}

	lblHeader := slack.NewTextBlockObject("plain_text", "Cloudtrail Tattletail event", false, false)
	secHeader := slack.NewHeaderBlock(lblHeader)

	msg := slack.WebhookMessage{
		Blocks: &slack.Blocks{
			BlockSet: []slack.Block{
				secHeader,
				nameSec,
				descSec,
				recSec,
			},
		},
	}

	if matchSec != nil {
		msg.Blocks.BlockSet = append(msg.Blocks.BlockSet, matchSec)
	}

	return slack.PostWebhook(d.webhookURL, &msg)
}

func textSec(label, text string) *slack.SectionBlock {
	lbl := slack.NewTextBlockObject("mrkdwn", label, false, false)
	fields := []*slack.TextBlockObject{
		slack.NewTextBlockObject("plain_text", text, false, false),
	}
	return slack.NewSectionBlock(lbl, fields, nil)
}

func codeSec(label, text string) *slack.SectionBlock {
	lbl := slack.NewTextBlockObject("mrkdwn", label, false, false)
	fields := []*slack.TextBlockObject{
		slack.NewTextBlockObject("mrkdwn", "```"+text+"```", false, true),
	}
	return slack.NewSectionBlock(lbl, fields, nil)
}
