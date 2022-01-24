// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pbkdf2

import (
	"encoding/binary"
)

// The size of a SHA256 checksum in bytes.
const hashLen = 32

// The blocksize of SHA256 in bytes.
const blockSize = 64

const (
	chunk = 64
	init0 = 0x6A09E667
	init1 = 0xBB67AE85
	init2 = 0x3C6EF372
	init3 = 0xA54FF53A
	init4 = 0x510E527F
	init5 = 0x9B05688C
	init6 = 0x1F83D9AB
	init7 = 0x5BE0CD19
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	h   [8]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7
	d.nx = 0
	d.len = 0
}

func (d *digest) BlockSize() int {
	return blockSize
}

func (d *digest) Size() int {
	return hashLen
}

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) Sum(in []byte) []byte {
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() [hashLen]byte {
	len := d.len
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	binary.BigEndian.PutUint64(tmp[:], len)
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [hashLen]byte
	binary.BigEndian.PutUint32(digest[0:], d.h[0])
	binary.BigEndian.PutUint32(digest[4:], d.h[1])
	binary.BigEndian.PutUint32(digest[8:], d.h[2])
	binary.BigEndian.PutUint32(digest[12:], d.h[3])
	binary.BigEndian.PutUint32(digest[16:], d.h[4])
	binary.BigEndian.PutUint32(digest[20:], d.h[5])
	binary.BigEndian.PutUint32(digest[24:], d.h[6])
	binary.BigEndian.PutUint32(digest[28:], d.h[7])
	return digest
}

// dirtySum copies the checksum to out, which must be exactly
// hashLen bytes.
//
// dirtySum modifies the digest's internal state.
func (d *digest) dirtySum(out []byte) {
	if len(out) != hashLen {
		panic("bad len")
	}
	hash := d.checkSum()
	copy(out, hash[:])
}

// writeBlock writes p, which must be exactly one block, to the
// digest.
//
// Can ony be used after writing one or more complete blocks to
// the digest.
func (d *digest) writeBlock(p []byte) {
	block(d, p)
}

// sumBlock copies the current checksum to p.
//
// p must be exactly hashLen bytes.
//
// Can only be used after writing one or more complete blocks to
// the digest.
func (d *digest) sumBlock(p []byte) {
	// Use p[n:m] prevents sumBlock from being inlined.
	binary.BigEndian.PutUint32(p[0:], d.h[0])
	binary.BigEndian.PutUint32(p[4:], d.h[1])
	binary.BigEndian.PutUint32(p[8:], d.h[2])
	binary.BigEndian.PutUint32(p[12:], d.h[3])
	binary.BigEndian.PutUint32(p[16:], d.h[4])
	binary.BigEndian.PutUint32(p[20:], d.h[5])
	binary.BigEndian.PutUint32(p[24:], d.h[6])
	binary.BigEndian.PutUint32(p[28:], d.h[7])
}

// xor sets d ^= v.
func (d *digest) xor(v *digest) {
	d.h[0] ^= v.h[0]
	d.h[1] ^= v.h[1]
	d.h[2] ^= v.h[2]
	d.h[3] ^= v.h[3]
	d.h[4] ^= v.h[4]
	d.h[5] ^= v.h[5]
	d.h[6] ^= v.h[6]
	d.h[7] ^= v.h[7]
}
