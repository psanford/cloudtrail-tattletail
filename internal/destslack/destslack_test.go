package destslack

import "testing"

func TestString(t *testing.T) {
	d := DestSlackWebhook{
		id:         "slack webhook",
		webhookURL: "https://hooks.slack.com/services/T00000000/B00000000/XXXX_SENSITIVE_URL_XXXX",
	}

	actual := d.String()
	expected := "{id: slack webhook webhookURL: https://hooks.slack.com/services/T00000000/B00000000/**FILTERED**}"
	if actual != expected {
		t.Errorf("expecting %s, got %s", expected, actual)
	}
}

func TestStringSimpleURL(t *testing.T) {
	d := DestSlackWebhook{
		id:         "slack webhook",
		webhookURL: "https://hooks.slack.com/services",
	}

	actual := d.String()
	expected := "{id: slack webhook webhookURL: https://hooks.slack.com/services}"
	if actual != expected {
		t.Errorf("expecting %s, got %s", expected, actual)
	}
}
