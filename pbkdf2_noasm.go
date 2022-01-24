//go:build !arm64 || !gc || purego

package pbkdf2

import "encoding/binary"

const pbkdf2Asm = false

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

	// inner1 is inner0 || salt.
	inner1 := inner0
	inner1.Write(salt)

	// U is an intermediate block reused by each iteration.
	//
	// It's padded out to blockSize in Merkle–Damgård form so
	// that the inner loop can write complete blocks.
	U := make([]byte, blockSize)
	U[hashLen] = 0x80
	binary.BigEndian.PutUint32(U[len(U)-4:], (blockSize+hashLen)*8)

	numBlocks := len(out) / hashLen
	for block := 1; block <= numBlocks; block++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:4], uint32(block))

		// U_1 = PRF(password, salt || uint(i))
		inner := inner1
		inner.Write(buf[:4])
		inner.dirtySum(U[:hashLen])

		outer := outer0
		outer.Write(U[:hashLen])
		outer.dirtySum(U[:hashLen])

		T := outer

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			inner := inner0
			inner.writeBlock(U[:])
			inner.sumBlock(U[:hashLen])

			outer := outer0
			outer.writeBlock(U[:])
			outer.sumBlock(U[:hashLen])

			T.xor(&outer)
		}

		T.sumBlock(out[:hashLen])
		out = out[hashLen:]
	}
}
