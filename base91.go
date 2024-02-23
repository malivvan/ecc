package ecc

import (
	"errors"
	"math"
)

// Base91 is a binary-to-text encoding scheme with a 91-character alphabet. Of the 95 printable ASCII characters, the
// following four are omitted: quotation mark (0x22), space (0x20), backtick (0x60) and backslash (0x5c).
var Base91 = newBase91Encoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_-{|}~'")

type base91Encoding struct {
	alphabet  [91]byte
	decodeMap [256]byte
}

func newBase91Encoding(alphabet string) *base91Encoding {
	e := new(base91Encoding)
	copy(e.alphabet[:], alphabet)
	for i := 0; i < len(e.decodeMap); i++ {
		e.decodeMap[i] = 0xff
	}
	for i := 0; i < len(alphabet); i++ {
		e.decodeMap[alphabet[i]] = byte(i)
	}
	return e
}

func (enc *base91Encoding) Encode(src []byte) string {
	dst := make([]byte, int(math.Ceil(float64(len(src))*16.0/13.0)))

	var queue, bits uint
	n := 0
	for i := 0; i < len(src); i++ {
		queue |= uint(src[i]) << bits
		bits += 8
		if bits > 13 {
			var v = queue & 8191
			if v > 88 {
				queue >>= 13
				bits -= 13
			} else {
				v = queue & 16383
				queue >>= 14
				bits -= 14
			}
			dst[n] = enc.alphabet[v%91]
			n++
			dst[n] = enc.alphabet[v/91]
			n++
		}
	}
	if bits > 0 {
		dst[n] = enc.alphabet[queue%91]
		n++
		if bits > 7 || queue > 90 {
			dst[n] = enc.alphabet[queue/91]
			n++
		}
	}

	return string(dst[:n])
}

func (enc *base91Encoding) Decode(s string) ([]byte, error) {
	dst := make([]byte, int(math.Ceil(float64(len(s))*14.0/16.0)))
	src := []byte(s)

	var queue, bits uint
	var v = -1
	n := 0
	for i := 0; i < len(src); i++ {
		if enc.decodeMap[src[i]] == 0xff {
			return nil, errors.New("invalid character")
		}
		if v == -1 {
			v = int(enc.decodeMap[src[i]])
		} else {
			v += int(enc.decodeMap[src[i]]) * 91
			queue |= uint(v) << bits
			if (v & 8191) > 88 {
				bits += 13
			} else {
				bits += 14
			}
			for ok := true; ok; ok = bits > 7 {
				dst[n] = byte(queue)
				n++

				queue >>= 8
				bits -= 8
			}
			v = -1
		}
	}
	if v != -1 {
		dst[n] = byte(queue | uint(v)<<bits)
		n++
	}

	return dst[:n], nil
}
