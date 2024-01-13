package dnscrypt

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPadUnpad(t *testing.T) {
	longBuf := make([]byte, 272)
	_, err := rand.Read(longBuf)
	assert.Nil(t, err)

	tests := []struct {
		packet       []byte
		expPaddedLen int
	}{
		{[]byte("Example Test DNS packet"), 256},
		{longBuf, 320},
	}
	for i, test := range tests {
		padded := pad(test.packet)
		assert.Equal(t, test.expPaddedLen, len(padded), "test %d", i)

		unpadded, err := unpad(padded)
		assert.Nil(t, err, "test %d", i)
		assert.Equal(t, test.packet, unpadded, "test %d", i)
	}
}

func TestIsDigit(t *testing.T) {
	tests := []struct {
		input byte
		exp   bool
	}{
		{byte('0'), true},
		{byte('3'), true},
		{byte('a'), false},
	}
	for i, test := range tests {
		ret := isDigit(test.input)
		assert.Equal(t, test.exp, ret, "test %d", i)
	}
}

func TestDDDToByte(t *testing.T) {
	tests := []struct {
		input []byte
		exp   byte
	}{
		{[]byte("100"), 100},
		{[]byte("247"), 247},
		{[]byte("255"), 255},
	}
	for i, test := range tests {
		ret := dddToByte(test.input)
		assert.Equal(t, test.exp, ret, "test %d", i)
	}
}
