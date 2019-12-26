# Makefile to build and deploy the SCRAMBLER service onto the server

BINFILE = bin/argonise

all:
	go build -mod=vendor -o $(BINFILE) -ldflags "-s -X main.BuildDate=$$(date +'%Y-%m-%dT%H:%M:%S') -X main.GitHash=$$(git rev-parse HEAD) -X main.Version=$$(git describe --tags 2> /dev/null || echo dev-version)"
