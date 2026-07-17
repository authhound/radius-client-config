package clientconfig

import (
	"crypto/rand"
	"fmt"
	"math"
)

// The two generation alphabets. The symbol set is deliberately small: every
// character survives clients.conf double quotes, PowerShell single quotes,
// and shells without escaping, and none of them ($ { }) can form a
// FreeRADIUS ${...} config expansion.
const (
	alnumChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	symbolChars = "!#%+,-./:=@^_~"
)

func charsetChars(name string) (string, error) {
	switch name {
	case CharsetAlnumSymbols:
		return alnumChars + symbolChars, nil
	case CharsetAlnum:
		return alnumChars, nil
	default:
		return "", fmt.Errorf("secret_charset %q: must be %q or %q", name, CharsetAlnumSymbols, CharsetAlnum)
	}
}

// generateSecret draws length characters uniformly from chars using
// crypto/rand. In a browser (GOOS=js) crypto/rand reads from the Web Crypto
// CSPRNG (crypto.getRandomValues); the WASM test page asserts that API is
// present before loading the module.
//
// Rejection sampling keeps the distribution unbiased: a random byte is used
// only if it falls below the largest multiple of len(chars) that fits in 256.
func generateSecret(length int, chars string) (string, error) {
	n := len(chars)
	if n < 2 || n > 256 {
		return "", fmt.Errorf("internal: charset size %d out of range", n)
	}
	limit := byte(256 - 256%n)
	out := make([]byte, 0, length)
	buf := make([]byte, 64)
	for len(out) < length {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("reading system randomness: %w", err)
		}
		for _, b := range buf {
			if limit != 0 && b >= limit {
				continue
			}
			out = append(out, chars[int(b)%n])
			if len(out) == length {
				break
			}
		}
	}
	return string(out), nil
}

// EntropyBits returns the whole bits of entropy in a secret of the given
// length drawn uniformly from a set of setSize symbols: floor(length *
// log2(setSize)). Exported so the website page can label user-tuned lengths
// without duplicating the math.
func EntropyBits(length, setSize int) int {
	if length <= 0 || setSize <= 1 {
		return 0
	}
	return int(math.Floor(float64(length) * math.Log2(float64(setSize))))
}
