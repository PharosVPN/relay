// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package onion

import (
	"errors"

	"golang.org/x/crypto/chacha20"
)

// Data-phase nonces. Forward (coxswain→node) and return (node→coxswain) use
// distinct nonces so the two directions never share a keystream. Each hop's key
// is unique (fresh per-circuit ECDH), so a fixed nonce per direction is safe.
var (
	nonceForward = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	nonceReturn  = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
)

// Layer is one hop's data-phase transform: a ChaCha20 keystream per direction.
// XOR is symmetric and length-preserving, so the same call both adds a layer
// (coxswain forward / relay return) and removes one (relay forward / coxswain
// return); hops apply their layer at matching stream positions, so there is no
// framing and no per-hop integrity. Integrity is end-to-end: the carried
// gRPC-mTLS or SSH payload authenticates itself, so a relay flipping bits can
// only cause that connection to drop — it cannot forge undetected.
//
// The two direction ciphers are independent, so a relay's forward and return
// pumps can run concurrently without sharing state.
type Layer struct {
	fwd, ret *chacha20.Cipher
}

// NewLayer builds a hop's data-phase layer from its session key.
func NewLayer(key []byte) (*Layer, error) {
	if len(key) != KeySize {
		return nil, errors.New("onion: bad session key size")
	}
	fwd, err := chacha20.NewUnauthenticatedCipher(key, nonceForward)
	if err != nil {
		return nil, err
	}
	ret, err := chacha20.NewUnauthenticatedCipher(key, nonceReturn)
	if err != nil {
		return nil, err
	}
	return &Layer{fwd: fwd, ret: ret}, nil
}

// Forward applies this hop's layer to forward-stream bytes (toward the node),
// in place. A relay calls it to peel its layer; the bytes must be processed in
// order so the keystream counter stays aligned with the other hops.
func (l *Layer) Forward(b []byte) { l.fwd.XORKeyStream(b, b) }

// Return applies this hop's layer to return-stream bytes (toward coxswain), in
// place. A relay calls it to add its layer.
func (l *Layer) Return(b []byte) { l.ret.XORKeyStream(b, b) }

// Stack is coxswain's full set of layers for a circuit (hop 0 … hop n-1) — the
// keys from Circuit.Keys. coxswain wraps every forward byte in all layers and
// unwraps every return byte from all layers.
type Stack struct{ layers []*Layer }

// NewStack builds coxswain's layer stack from the per-hop session keys.
func NewStack(keys [][]byte) (*Stack, error) {
	if len(keys) == 0 {
		return nil, errors.New("onion: empty key set")
	}
	ls := make([]*Layer, len(keys))
	for i, k := range keys {
		l, err := NewLayer(k)
		if err != nil {
			return nil, err
		}
		ls[i] = l
	}
	return &Stack{layers: ls}, nil
}

// Forward wraps forward-stream bytes (heading to the node) in every layer.
func (s *Stack) Forward(b []byte) {
	for _, l := range s.layers {
		l.Forward(b)
	}
}

// Return unwraps return-stream bytes (coming from the node) from every layer.
func (s *Stack) Return(b []byte) {
	for _, l := range s.layers {
		l.Return(b)
	}
}
