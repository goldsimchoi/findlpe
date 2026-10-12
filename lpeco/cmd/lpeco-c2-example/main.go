package main

import (
	"context"
	"fmt"
	"os"

	"github.com/normalone/lpeco/internal/adapter/plugin"
)

func main() {
	backend := newBackend()
	if err := plugin.ServeJSONL(context.Background(), os.Stdin, os.Stdout, 1024*1024, func(_ context.Context, request plugin.Request) plugin.Response {
		return backend.handle(request)
	}); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "lpeco-c2-example: %v\n", err)
		os.Exit(1)
	}
}
