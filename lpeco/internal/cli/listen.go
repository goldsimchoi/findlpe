package cli

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/adapter/raw"
)

func listenRaw(ctx context.Context, configuration Config, status io.Writer) (adapter.Adapter, error) {
	connection, err := raw.Listen(ctx, raw.ListenerOptions{
		Bind: configuration.Raw.Bind, AllowPublicBind: configuration.Raw.AllowPublicBind, AcceptTimeout: configuration.Raw.AcceptTimeout,
		Ready: func(address net.Addr) { _, _ = fmt.Fprintf(status, "raw listener ready on %s\n", address.String()) },
	})
	if err != nil {
		return nil, err
	}
	return raw.New(connection, raw.Options{
		TransportKind: "raw-listen", Interactive: configuration.Raw.Interactive, TTY: configuration.Raw.TTY,
		MaxOutputBytes: configuration.Common.MaxOutput,
	}), nil
}
