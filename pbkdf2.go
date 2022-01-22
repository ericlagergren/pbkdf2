// Package pbkdf2 implements an optimized PBKDF2 (SHA-256 only).
package pbkdf2

import (
	"encoding/binary"
)

// Key derives a key from password, salt, and iteration count
// using PBKDF-HMAC-SHA256.
//
// The key will be keyLen bytes long. Etc. You know the rest.
func Key(password, salt []byte, iter, keyLen int) []byte {
	// outer0 is HMAC's outer hash function set to the outer
	// padding.
	var outer0 digest
	outer0.Reset()

	// Truncate if necessary.
	key := password
	if len(key) > blockSize {
		outer0.Write(key)
		key = outer0.Sum(nil)
	}

	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	copy(ipad, key)
	copy(opad, key)
	for i := 0; i < blockSize; i++ {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}
	outer0.Write(opad)

	// inner0 is HMAC's inner hash function set to the inner
	// padding.
	var inner0 digest
	inner0.Reset()
	inner0.Write(ipad)

	// inner1 is inner0 || salt.
	inner1 := inner0
	inner1.Write(salt)

	out := make([]byte, ((keyLen+hashLen-1)/hashLen)*hashLen)
	ret := out

	// U is an intermediate block reused by each iteration.
	//
	// It's padded out to blockSize in Merkle–Damgård form so
	// that the inner loop can write complete blocks.
	var U [blockSize]byte
	U[hashLen] = 0x80
	binary.BigEndian.PutUint32(U[len(U)-4:], (blockSize+hashLen)*8)

	for i := 1; len(out) >= hashLen; i++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:4], uint32(i))

		// U_1 = PRF(password, salt || uint(i))
		inner := inner1
		inner.Write(buf[:4])
		inner.dirtySum(U[:hashLen])

		outer := outer0
		outer.Write(U[:hashLen])
		outer.dirtySum(U[:hashLen])

		sum := outer.h

		// U_n = PRF(password, U_(n-1))
		sha256inner(&sum, &inner0.h, &outer0.h, &U, &_K, iter)

		binary.BigEndian.PutUint32(out[0:], sum[0])
		binary.BigEndian.PutUint32(out[4:], sum[1])
		binary.BigEndian.PutUint32(out[8:], sum[2])
		binary.BigEndian.PutUint32(out[12:], sum[3])
		binary.BigEndian.PutUint32(out[16:], sum[4])
		binary.BigEndian.PutUint32(out[20:], sum[5])
		binary.BigEndian.PutUint32(out[24:], sum[6])
		binary.BigEndian.PutUint32(out[28:], sum[7])

		out = out[hashLen:]
	}
	return ret[:keyLen]
}
