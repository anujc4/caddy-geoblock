.PHONY: test build lint clean

# Run all tests
test:
	go test -v -race ./...

# Build Caddy with the geoblock module
build:
	xcaddy build --with github.com/anujc4/caddy-geoblock=.

# Run golangci-lint
lint:
	golangci-lint run ./...

# Clean build artifacts
clean:
	rm -f caddy
