BINARY := vpcproxy
MODULE := github.com/dulltz/vpcproxy

.PHONY: build test vet fmt-check clean

build:
	CGO_ENABLED=0 go build -o $(BINARY) .

test:
	go test -race -shuffle=on -v ./...

vet:
	go vet ./...

fmt-check:
	test -z "$$(goimports -l .)"

clean:
	rm -f $(BINARY)
