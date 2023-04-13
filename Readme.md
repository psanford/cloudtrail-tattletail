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
jq_match = '''
select(.eventName == "CreateUser") |
"username: \(.responseElements.user.userName)"
'''
description = "A new IAM user has been created"
destinations = ["Default SNS", "Slack Warnings", "Email"]

[[rule]]
name = "Create AccessKey"
jq_match = 'select(.eventName == "CreateAccessKey")'
description = "A new Access Key has been created"
destinations = ["Default SNS", "Slack Warnings", "Email"]

[[rule]]
name = "Modifications"
# match any event that doesn't begin with List,Get,Describe,etc.
jq_match = 'select(.eventName|test("^(List|Get|Describe|AssumeRole|Decrypt|CreateLog|ConsoleLogin)")|not)'
description = 'A config change occurred'
# just send this to Slack
destinations = ["Slack Warnings"]

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

# Writing jq_match queries

Each cloud trail event is tested against `jq_match` individually. This means your jq should not include a top level `.records[]`. If you want
to test your `jq_match` query against a cloudtrail log you can do it like this:

```
# assuming your jq_match = 'select(.eventName == "CreateAccessKey")'

# get the stream of cloudtrail events:
$ jq '.Records[]' 364679954851_CloudTrail_us-east-1_20210713T1540Z_DWktkdMpEvhK04Eq.json > cloudtrail.stream.json

# run the jq_match query against the stream file
$ jq 'select(.eventName == "CreateAccessKey")' cloudtrail.stream.json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789:assumed-role/admin_read_write/AWSCLI-Session",
    "accountId": "123456789",
    "sessionContext": {
      "sessionIssuer": {
        "type": "Role",
        "arn": "arn:aws:iam::123456789:role/admin",
        "accountId": "123456789",
        "userName": "admin"
      },
      "webIdFederationData": {},
      "attributes": {
        "mfaAuthenticated": "true",
        "creationDate": "2021-07-13T14:59:19Z"
      }
    }
  },
  "eventTime": "2021-07-13T15:30:43Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateAccessKey",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "1.1.1.1",
  "userAgent": "console.amazonaws.com",
  "requestParameters": {
    "userName": "nopermuser"
  },
  "responseElements": {
    "accessKey": {
      "userName": "nopermuser",
      "status": "Active",
      "createDate": "Jul 13, 2021 3:30:43 PM"
    }
  },
  "requestID": "c6325cf0-ea6e-48ea-b2bd-2df2630ce790",
  "eventID": "7f234c0f-61d9-4d9e-add6-f767474d9be6",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "eventCategory": "Management",
  "recipientAccountId": "123456789"
}
```

Cloudtrail Tattletail will only alert on queries that return a non-null, non-false value.

### Advanced jq_matching

Cloudtrail Tattletail will annotate alerts with custom formatted output of any jq expression that evaluates to something other than the full cloudtrail record.  For example. to include the username of a `CreateUser` event as the annotation you could use the following `jq_match`:

```
jq_match = 'select(.eventName == "CreateUser") | "username: \(.responseElements.user.userName)"'

# this outputs:
"username: hacker1"
```

If you do not want to include any match metadata with the alerts use `select()`:

```
jq_match = 'select(.eventName == "CreateUser")
```

# Screenshots

### Slack Webhook
<img src="https://raw.githubusercontent.com/psanford/cloudtrail-tattletail/main/screenshots/slack-webhook.png?raw=true" alt="Slack Webhook" />

### Email (SES)
<img src="https://raw.githubusercontent.com/psanford/cloudtrail-tattletail/main/screenshots/email.png?raw=true" alt="Email" />
