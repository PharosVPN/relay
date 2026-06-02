// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package onion is the control-plane onion-routing crypto (DESIGN §3, decision
// 20). coxswain Builds a layered setup onion for a fixed relay path; each relay
// Peels its own layer with its X25519 onion key, learning only its next hop and
// its per-hop session key — never coxswain's identity or the rest of the path.
// The session keys feed the data-phase layered AEAD (see seal.go).
//
// Setup is single-pass (Sphinx/HORNET-style): each layer is sealed to the
// relay's onion public key via an ephemeral ECDH, so there is no interactive
// per-hop handshake. A layer is:
//
//	eph_pub(32) ‖ ChaCha20-Poly1305(K; nonce=0; flags(1) ‖ addrLen(2) ‖ addr ‖ inner)
//	K = HKDF-SHA256(ECDH(eph, onionPub), info="pharos-onion-v1 setup")
//
// The all-zero nonce is safe: each K is derived from a fresh ephemeral key and
// used for exactly one seal.
package onion

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// KeySize is the per-hop session-key length (ChaCha20-Poly1305).
const KeySize = chacha20poly1305.KeySize

const (
	setupInfo  = "pharos-onion-v1 setup"
	ephLen     = 32 // X25519 public key
	flagExit   = 0x01
	maxAddrLen = 255
)

// Hop is one relay on the path: its onion public key, plus the address the
// previous hop dials to reach it (its `beacon egress` onion endpoint).
type Hop struct {
	Addr     string
	OnionPub *ecdh.PublicKey
}

// Circuit is coxswain's built onion: Setup is the blob to hand the first hop;
// Keys are the per-hop session keys, hop 0 first, for the data phase.
type Circuit struct {
	Setup []byte
	Keys  [][]byte
}

// Build constructs the nested setup onion for hops[0..n-1], terminating in a
// CONNECT to target at the last hop. hops[0] is the first relay coxswain dials.
func Build(hops []Hop, target string) (*Circuit, error) {
	if len(hops) == 0 {
		return nil, errors.New("onion: need at least one hop")
	}
	if target == "" {
		return nil, errors.New("onion: empty target")
	}
	keys := make([][]byte, len(hops))

	// Innermost (exit) layer first, then wrap outward.
	var inner []byte
	for i := len(hops) - 1; i >= 0; i-- {
		addr := target
		flags := byte(flagExit)
		if i < len(hops)-1 {
			addr = hops[i+1].Addr // forward to the next relay
			flags = 0
		}
		if len(addr) > maxAddrLen {
			return nil, fmt.Errorf("onion: hop %d addr too long", i)
		}
		layer, key, err := sealLayer(hops[i].OnionPub, flags, addr, inner)
		if err != nil {
			return nil, fmt.Errorf("onion: seal hop %d: %w", i, err)
		}
		keys[i] = key
		inner = layer
	}
	return &Circuit{Setup: inner, Keys: keys}, nil
}

// Peeled is what a relay learns from opening its setup layer.
type Peeled struct {
	Key      []byte // this hop's session key, for the data phase
	NextAddr string // next relay to forward to, or the final target at the exit
	Inner    []byte // setup onion for the next relay; empty at the exit
	Exit     bool   // true → NextAddr is the node target; dial it and relay data
}

// Peel opens the outermost layer of setup with this relay's onion private key.
func Peel(setup []byte, priv *ecdh.PrivateKey) (*Peeled, error) {
	if len(setup) < ephLen {
		return nil, errors.New("onion: setup shorter than ephemeral key")
	}
	ephPub, err := ecdh.X25519().NewPublicKey(setup[:ephLen])
	if err != nil {
		return nil, fmt.Errorf("onion: bad ephemeral key: %w", err)
	}
	key, err := deriveKey(priv, ephPub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, make([]byte, aead.NonceSize()), setup[ephLen:], nil)
	if err != nil {
		return nil, fmt.Errorf("onion: open layer: %w", err)
	}
	flags, addr, inner, err := parsePayload(pt)
	if err != nil {
		return nil, err
	}
	return &Peeled{
		Key:      key,
		NextAddr: addr,
		Inner:    inner,
		Exit:     flags&flagExit != 0,
	}, nil
}

// sealLayer builds one layer sealed to pub, returning the layer and the session
// key derived for it.
func sealLayer(pub *ecdh.PublicKey, flags byte, addr string, inner []byte) (layer, key []byte, err error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	key, err = deriveKey(eph, pub)
	if err != nil {
		return nil, nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, err
	}
	pt := make([]byte, 0, 1+2+len(addr)+len(inner))
	pt = append(pt, flags)
	pt = binary.BigEndian.AppendUint16(pt, uint16(len(addr)))
	pt = append(pt, addr...)
	pt = append(pt, inner...)

	ct := aead.Seal(nil, make([]byte, aead.NonceSize()), pt, nil)
	layer = make([]byte, 0, ephLen+len(ct))
	layer = append(layer, eph.PublicKey().Bytes()...)
	layer = append(layer, ct...)
	return layer, key, nil
}

// parsePayload splits a decrypted layer into flags, addr and the inner onion.
func parsePayload(pt []byte) (flags byte, addr string, inner []byte, err error) {
	if len(pt) < 3 {
		return 0, "", nil, errors.New("onion: layer payload too short")
	}
	flags = pt[0]
	addrLen := int(binary.BigEndian.Uint16(pt[1:3]))
	if 3+addrLen > len(pt) {
		return 0, "", nil, errors.New("onion: addr length overflows payload")
	}
	addr = string(pt[3 : 3+addrLen])
	inner = pt[3+addrLen:]
	return flags, addr, inner, nil
}

// deriveKey computes the per-hop session key from an ECDH shared secret.
func deriveKey(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("onion: ecdh: %w", err)
	}
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, []byte(setupInfo)), key); err != nil {
		return nil, fmt.Errorf("onion: hkdf: %w", err)
	}
	return key, nil
}
