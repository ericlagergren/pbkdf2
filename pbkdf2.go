// Package pbkdf2 implements an optimized PBKDF2 (SHA-256 only).
package pbkdf2

// Key derives a key from password, salt, and iteration count
// using PBKDF-HMAC-SHA256.
//
// The key will be keyLen bytes long, etc. You know the rest.
func Key(password, salt []byte, iter, keyLen int) []byte {
	out := make([]byte, ((keyLen+hashLen-1)/hashLen)*hashLen)
	key(out, password, salt, iter)
	return out[:keyLen]
}
