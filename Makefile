BINARY := vpcproxy
MODULE := github.com/dulltz/vpcproxy

.PHONY: build test vet fmt-check clean

build:
	go build -o $(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

fmt-check:
	test -z "$$(gofmt -l .)"

clean:
	rm -f $(BINARY)
