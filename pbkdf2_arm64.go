//go:build gc && !purego

package pbkdf2

import (
	"encoding/binary"
)

const pbkdf2Asm = true

func key(out, password, salt []byte, iter int) {
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

	// inner1 := inner0 || salt.
	inner1 := inner0
	inner1.Write(salt)

	// U is an intermediate block reused by each iteration.
	//
	// It's padded out to blockSize in Merkle–Damgård form so
	// that the inner loop can write complete blocks.
	var U [blockSize]byte
	U[hashLen] = 0x80
	binary.BigEndian.PutUint32(U[len(U)-4:], (blockSize+hashLen)*8)
	// fmt.Printf("B: %x %x %x %x\n",
	// 	binary.LittleEndian.Uint64(U[32:40]),
	// 	binary.LittleEndian.Uint64(U[40:48]),
	// 	binary.LittleEndian.Uint64(U[48:56]),
	// 	binary.LittleEndian.Uint64(U[56:64]))

	j := 0
	for i := 1; j < len(out); i++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:4], uint32(i))

		// U_1 = PRF(password, salt || uint(i))
		inner := inner1
		inner.Write(buf[:4])
		inner.dirtySum(U[:hashLen])

		outer := outer0
		outer.Write(U[:hashLen])
		outer.dirtySum(U[:hashLen])

		sha256inner(&out[j], &outer.h, &inner0.h, &outer0.h, &U, &_K, iter)
		j += hashLen
	}
	// fmt.Printf("A: %x %x %x %x\n",
	// 	binary.LittleEndian.Uint64(U[32:40]),
	// 	binary.LittleEndian.Uint64(U[40:48]),
	// 	binary.LittleEndian.Uint64(U[48:56]),
	// 	binary.LittleEndian.Uint64(U[56:64]))
	// println()
}
