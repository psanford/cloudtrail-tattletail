BIN=cloudtrail-tattletail
FUNCTION_NAME=$(BIN)
CONF_S3_BUCKET=
CONF_S3_PATH=

$(BIN): $(wildcard *.go) $(wildcard **/*.go)
	go test .
	go build -o $(BIN)

$(BIN).zip: $(BIN) $(wildcard ./tattletail.toml)
	rm -f $@
	zip -r $@ $^

.PHONY: upload
upload: $(BIN).zip
	aws lambda update-function-code --function-name $(FUNCTION_NAME) --zip-file fileb://$(BIN).zip
	rm $(BIN).zip

.PHONY: upload_config
upload_config: $(BIN).toml
	aws s3 cp $^ "s3://$(CONF_S3_BUCKET)/$(CONF_S3_PATH)"
