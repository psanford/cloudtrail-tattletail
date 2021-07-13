package config

type Config struct {
	Rules        []Rule        `toml:"rule"`
	Destinations []Destination `toml:"destination"`
}

type Rule struct {
	Name         string   `toml:"name"`
	JQMatch      string   `toml:"jq_match"`
	Destinations []string `toml:"destinations"`
	Desc         string   `toml:"description"`
}

type Destination struct {
	ID string `toml:"id"`
	// Type is a string of "sns" "slack_webhook" "ses"
	Type string `toml:"type"`

	// SNSARN is for type "sns"
	SNSARN string `toml:"sns_arn"`

	// WebhookURL is for type "slack_webhook"
	WebhookURL string `toml:"webhook_url"`

	// ToEmails is for type "ses"
	ToEmails []string `toml:"to_emails"`
	// FromEmail is for type "ses"
	FromEmail string `toml:"from_email"`
}
