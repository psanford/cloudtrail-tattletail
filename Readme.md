# Cloudtail-Tattletail

Cloudtrail-Tattletail is a Lambda based Cloudtrail alerting tool. It allows you to write simple rules for interesting Cloudtrail events and forward those events to a number of different systems.

Cloudtrail-Tattletail is designed to run with a minimal set of dependencies to make it easy to get up and alerting without needing to setup a lot of different AWS services. The only hard requirement is that you enable S3 events to trigger the Tattletail lambda function from the S3 bucket that your Cloudtrail logs are going to.

Currently Cloudtrail-Tattletail supports the following destinations to forward alerts to:
- SNS Topic
- Email Address (via SES)
- Slack Channel (via slack_webhook)

Forwarding to an SNS Topic allows for easy extensibility.

## Configuration

There are two basic things you need to configure to start using Cloudtrail-Tattletail: Rules and Destinations.

Rules describe which events should be forwarded and alerted on. Rules are written in the `jq` [query language](https://stedolan.github.io/jq/manual/). This makes it easy to write both simple and complex matching logic.

Each rule that matches an event will be forwarded to all the destinations listed in the rule.

Destinations are the upstream service that the alert should be forwarded to.

### Setup

1. Create a configuration file with your alert rules and destinations.
1. Enable cloudtrail logging to an S3 bucket.
1. Create a Go lambda function
1. Grant the lambda function access to the cloudtrail s3 bucket
1. Add an s3 trigger to invoke the lambda function for new files
1. Add permissions for SNS and SES if you are using those destinations

#### Configuration example

```
[[rule]]
name = "Create User"
jq_match = 'select(.eventName == "CreateUser") | "username: \(.responseElements.user.userName)"'
description = "A new IAM user has been created"
destinations = ["Default SNS", "Slack Warnings", "Email"]

[[rule]]
name = "Create AccessKey"
jq_match = 'select(.eventName == "CreateAccessKey")'
description = "A new Access Key has been created"
destinations = ["Default SNS", "Slack Warnings", "Email"]

[[destination]]
id = "Default SNS"
type = "sns"
sns_arn = "arn:aws:sns:us-east-1:1234567890:cloudtail_alert"

[[destination]]
id = "Slack Warnings"
type = "slack_webhook"
webhook_url = "https://foo.slack.com/some/webhook/url"

[[destination]]
id = "Email"
type = "ses"
to_emails = ["foo@example.com", "bar@example.com"]
from_email = "cloudtrail_alerts@example.com"
```

The configuration file can either be bundled directly in lambda function, or it can be uploaded to an S3 bucket and the lambda function will fetch it when it is invoked. Bundling the configuration file directly is simpler but you have to reupload the whole lambda function any time you want to make configuration changes.

To include the configuration file directly in the lambda function simply create a file named `tattletail.toml` in the cloudtrail-tattletail working directory. Running `make cloudtrail-tattletail.zip` will include the configuration in the zip bundle file if it is present.

To load the configuration from an S3 bucket set the following environment variables on the Lambda function `S3_CONFIG_BUCKET` and `S3_CONFIG_PATH`. Make sure the Lambda function has permission to GetObject for that bucket + path.

If the s3 config environment variables are set they will take precedence over any bundled config file.

#### Lambda Function

To build the Lambda function code bundle run `make cloudtrail-tattletail.zip`.

Create a Go Lambda function. Upload the `cloudtrail-tattletail.zip` file as the code bundle.

Add an s3 trigger from your CloudTrail s3 bucket.

Add any permissions for invoking SNS or SES if you are using those destination types.

# Screenshots

### Slack Webhook
<img src="https://raw.githubusercontent.com/psanford/cloudtrail-tattletail/main/screenshots/slack-webhook.png?raw=true" alt="Slack Webhook" />

### Email (SES)
<img src="https://raw.githubusercontent.com/psanford/cloudtrail-tattletail/main/screenshots/email.png?raw=true" alt="Email" />
