// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pbkdf2

import "golang.org/x/sys/cpu"

//go:noescape
func sha256block(h []uint32, p []byte, k []uint32)

//go:noescape
func sha256inner(out *byte, sum, inner0, outer0 *[8]uint32, U *[blockSize]byte, k *[64]uint32, iter int)

func block(dig *digest, p []byte) {
	if !cpu.ARM64.HasSHA2 {
		blockGeneric(dig, p)
	} else {
		h := dig.h[:]
		sha256block(h, p, _K[:])
	}
}
