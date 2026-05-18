// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package proxy

import (
	"fmt"

	"google.golang.org/grpc/encoding"
	_ "google.golang.org/grpc/encoding/proto"
)

// rawCodec shuttles payloads through gRPC without touching the wire
// bytes. The relay never needs to decode messages — it only forwards
// them — so we register a codec that treats the frame as opaque.
//
// Registered under "proto" so it wins over the default proto codec
// on streams we create with grpc.ForceCodec(rawCodec{}). We take
// pains not to call RegisterCodec, which would globally replace the
// real proto codec and break every other gRPC user in the process.
type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }

func (rawCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*frame)
	if !ok {
		return nil, fmt.Errorf("proxy: rawCodec.Marshal got %T, want *frame", v)
	}
	return b.data, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	b, ok := v.(*frame)
	if !ok {
		return fmt.Errorf("proxy: rawCodec.Unmarshal into %T, want *frame", v)
	}
	b.data = make([]byte, len(data))
	copy(b.data, data)
	return nil
}

// frame is the message type we pass through gRPC's codec path. A
// typed wrapper (not []byte) so we can distinguish it from every
// other codec user and fail loudly on type confusion.
type frame struct{ data []byte }

// ensure rawCodec satisfies encoding.Codec — compile-time check.
var _ encoding.Codec = rawCodec{}
