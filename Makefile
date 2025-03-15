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

.PHONY: proto-gen
proto-gen:
	buf generate --config ./buf.yaml --template ./buf.gen.yaml

.PHONY: proto-build
proto-build:
	buf build --config ./buf.yaml

.PHONY: proto-lint
proto-lint:
	buf lint --config ./buf.yaml