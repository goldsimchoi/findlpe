package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/normalone/lpeco/internal/cli"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(cli.Execute(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
