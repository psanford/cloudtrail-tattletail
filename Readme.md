# CLoudtail-Tattletail

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
