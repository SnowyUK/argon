# Makefile to build and deploy the SCRAMBLER service onto the server

BINFILE = bin/argonise

all:
	go build -mod=vendor -o $(BINFILE) -ldflags "-s -X argon.Version.BuildDate=$$(date +'%Y-%m-%dT%H:%M:%S') -X argon.Version.GitHash=$$(git rev-parse HEAD) -X argon.Version.Version=$$(git describe --tags 2> /dev/null || echo dev-version)"
