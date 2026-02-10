BINARY := vpcproxy
MODULE := github.com/dulltz/vpcproxy

.PHONY: build test clean

build:
	go build -o $(BINARY) .

test:
	go test ./...

clean:
	rm -f $(BINARY)
