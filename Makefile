.PHONY: lint
lint:
	golangci-lint run --config .github/golangci.yaml

.PHONY: gofumpt
gofumpt:
	go install mvdan.cc/gofumpt@latest
	gofumpt -l -w .

.PHONY: fixalign
fixalign:
	go install golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment@latest
	fieldalignment -fix $(filter-out $@,$(MAKECMDGOALS)) # the full package name (not path!)

.PHONY: proto
proto:
	protoc --proto_path=proto --go_out=. --go-grpc_out=. proto/*.proto
