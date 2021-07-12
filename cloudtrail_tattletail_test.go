package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/google/go-cmp/cmp"
	"github.com/psanford/cloudtrail-tattletail/awsstub"
	"github.com/psanford/cloudtrail-tattletail/internal/destsns"
)

var (
	fakeS3      = make(map[bucketKey][]byte)
	snsMessages []destsns.Payload
)

func TestRuleMatchingSNS(t *testing.T) {
	awsstub.S3GetObj = fakeGetObj
	awsstub.SnsPublish = fakeSNSPublish

	jsonTxt, err := ioutil.ReadFile("testdata/1.json")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)

	_, err = io.Copy(w, bytes.NewReader(jsonTxt))
	if err != nil {
		t.Fatal(err)
	}

	err = w.Close()
	if err != nil {
		t.Fatal(err)
	}

	bucketName := "interlinked-buzzards"
	fileName := "supplants-streptococcal.json.gz"

	_, err = fakePutObj(&s3manager.UploadInput{
		Body:   &buf,
		Key:    &fileName,
		Bucket: &bucketName,
	})
	if err != nil {
		t.Fatal(err)
	}

	config := `
[[rule]]
name = "Create User"
jq_match = 'select(.eventName == "CreateUser") | "username: \(.responseElements.user.userName)"'
destinations = ["Default SNS"]
description = "A new IAM user has been created"

[[destination]]
id = "Default SNS"
type = "sns"
sns_arn = "arn:aws:sns:us-east-1:1234567890:cloudtail_alert"
`

	confBucket := "mandrake-Aquarius"
	confKey := "horseplay-shoveling.toml"
	_, err = fakePutObj(&s3manager.UploadInput{
		Body:   bytes.NewBufferString(config),
		Key:    &confKey,
		Bucket: &confBucket,
	})
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv("S3_CONFIG_BUCKET", confBucket)
	os.Setenv("S3_CONFIG_PATH", confKey)
	os.Setenv("AWS_REGION", "us-east-1")

	server := newServer()
	err = server.Handler(events.S3Event{
		Records: []events.S3EventRecord{
			{
				S3: events.S3Entity{
					Bucket: events.S3Bucket{
						Name: bucketName,
					},
					Object: events.S3Object{
						Key: fileName,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Records []map[string]interface{} `json:"records"`
	}
	err = json.Unmarshal(jsonTxt, &doc)
	if err != nil {
		t.Fatal(err)
	}

	expect := []destsns.Payload{
		{
			Name:   "Create User",
			Desc:   "A new IAM user has been created",
			Record: doc.Records[1],
			Match:  "username: user1",
		},
	}

	if !cmp.Equal(snsMessages, expect) {
		t.Fatal(cmp.Diff(snsMessages, expect))
	}

}

func fakeGetObj(i *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	key := bucketKey{*i.Bucket, *i.Key}
	if obj, found := fakeS3[key]; found {
		out := &s3.GetObjectOutput{
			Body: ioutil.NopCloser(bytes.NewReader(obj)),
		}
		return out, nil
	}

	return nil, awserr.New(s3.ErrCodeNoSuchKey, s3.ErrCodeNoSuchKey, nil)
}

func fakePutObj(i *s3manager.UploadInput, o ...func(*s3manager.Uploader)) (*s3manager.UploadOutput, error) {
	b, err := ioutil.ReadAll(i.Body)
	if err != nil {
		return nil, err
	}

	key := bucketKey{*i.Bucket, *i.Key}
	fakeS3[key] = b

	return &s3manager.UploadOutput{}, nil
}

type bucketKey struct {
	bucket string
	key    string
}

func fakeSNSPublish(i *sns.PublishInput) (*sns.PublishOutput, error) {
	var msg destsns.Payload

	err := json.Unmarshal([]byte(*i.Message), &msg)
	if err != nil {
		panic(err)
	}

	snsMessages = append(snsMessages, msg)
	return nil, nil
}
