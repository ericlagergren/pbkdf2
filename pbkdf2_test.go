package pbkdf2

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

type testVector struct {
	password string
	salt     string
	iter     int
	output   []byte
}

// Test vectors from
// http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
var sha256TestVectors = []testVector{
	{
		"password",
		"salt",
		1,
		[]byte{
			0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
			0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
			0xa8, 0x65, 0x48, 0xc9,
		},
	},
	{
		"password",
		"salt",
		2,
		[]byte{
			0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3,
			0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
			0x2a, 0x30, 0x3f, 0x8e,
		},
	},
	{
		"password",
		"salt",
		4096,
		[]byte{
			0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41,
			0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
			0x96, 0x28, 0x93, 0xa0,
		},
	},
	{
		"passwordPASSWORDpassword",
		"saltSALTsaltSALTsaltSALTsaltSALTsalt",
		4096,
		[]byte{
			0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f,
			0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
			0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
			0x1c,
		},
	},
	{
		"pass\000word",
		"sa\000lt",
		4096,
		[]byte{
			0x89, 0xb6, 0x9d, 0x05, 0x16, 0xf8, 0x29, 0x89,
			0x3c, 0x69, 0x62, 0x26, 0x65, 0x0a, 0x86, 0x87,
		},
	},
}

func testHash(t *testing.T, h func() hash.Hash, hashName string, vectors []testVector) {
	for i, v := range vectors {
		o := Key([]byte(v.password), []byte(v.salt), v.iter, len(v.output))
		if !bytes.Equal(o, v.output) {
			t.Errorf("%s #%d: expected %x, got %x", hashName, i, v.output, o)
		}
	}
}

func TestWithHMACSHA256(t *testing.T) {
	testHash(t, sha256.New, "SHA256", sha256TestVectors)
}

func TestFuzz(t *testing.T) {
	password := make([]byte, 32)
	salt := make([]byte, 8)
	for iters := 32; iters < 4096; iters *= 2 {
		for keyLen := 32; keyLen < 4096; keyLen *= 2 {
			want := pbkdf2.Key(password, salt, iters, keyLen, sha256.New)
			got := Key(password, salt, iters, keyLen)
			if !bytes.Equal(want, got) {
				t.Fatalf("expected %x, got %x", want, got)
			}
		}
	}
}

var sink uint8

func BenchmarkHMACSHA256(b *testing.B) {
	const iter = 4096
	password := make([]byte, sha256.Size)
	b.SetBytes(int64(len(password)) * iter * 2)
	salt := make([]byte, 8)
	for i := 0; i < b.N; i++ {
		password = Key(password, salt, iter, len(password))
	}
	sink += password[int(sink)%len(password)]
}

func BenchmarkHMACSHA256_Go(b *testing.B) {
	const iter = 4096
	password := make([]byte, sha256.Size)
	b.SetBytes(int64(len(password)) * iter * 2)
	salt := make([]byte, 8)
	for i := 0; i < b.N; i++ {
		password = pbkdf2.Key(password, salt, 4096, len(password), sha256.New)
	}
	sink += password[int(sink)%len(password)]
}
