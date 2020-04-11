NAME=socksproxy
BINDIR=.

all: linux macos

linux:
	GOARCH=amd64 GOOS=linux go build -o $(BINDIR)/$(NAME)-$@

macos:
	GOARCH=amd64 GOOS=darwin go build -o $(BINDIR)/$(NAME)-$@
