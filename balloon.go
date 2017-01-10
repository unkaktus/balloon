// balloon.go - implementation of Balloon memory-hard hashing.
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of blake2xb, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package balloon

import (
	"encoding/binary"
	"hash"
	"math/big"
)

const (
	delta = 3
)

// Balloon uses non-memory-hard cryptographic hash function h
// and calculates memory-hard Ballon hash of passphrase with salt.
// sCost is the number of digest-sized blocks in buffer (space cost).
// tCost is the number of rounds (time cost).
func Balloon(h hash.Hash, passphrase, salt []byte, sCost, tCost uint64) []byte {
	var cnt uint64
	blockSize := uint64(h.Size())
	buf := make([]byte, sCost*blockSize)

	h.Reset()
	binary.Write(h, binary.BigEndian, cnt)
	cnt++
	h.Write(passphrase)
	h.Write(salt)
	prevBlock := h.Sum(nil)
	copy(buf, prevBlock)

	for m := uint64(1); m < sCost; m++ {
		h.Reset()
		binary.Write(h, binary.BigEndian, cnt)
		h.Write(prevBlock)
		prevBlock = h.Sum(nil)
		copy(buf[cnt*blockSize:], prevBlock)
		cnt++
	}
	sCostInt := big.NewInt(int64(sCost))
	otherInt := big.NewInt(0)

	for t := uint64(0); t < tCost; t++ {
		for m := uint64(0); m < sCost; m++ {
			h.Reset()
			binary.Write(h, binary.BigEndian, cnt)
			cnt++
			h.Write(prevBlock)
			h.Write(buf[m*blockSize : (m+1)*blockSize])
			prevBlock = h.Sum(nil)
			copy(buf[m*blockSize:], prevBlock)

			for i := uint64(0); i < delta; i++ {
				h.Reset()
				binary.Write(h, binary.BigEndian, cnt)
				cnt++
				h.Write(salt)
				binary.Write(h, binary.BigEndian, t)
				binary.Write(h, binary.BigEndian, m)
				binary.Write(h, binary.BigEndian, i)
				otherInt.SetBytes(h.Sum(nil))
				otherInt.Mod(otherInt, sCostInt)
				other := otherInt.Uint64()
				h.Reset()
				binary.Write(h, binary.BigEndian, cnt)
				cnt++
				h.Write(prevBlock)
				h.Write(buf[other*blockSize : (other+1)*blockSize])
				prevBlock = h.Sum(nil)
				copy(buf[m*blockSize:], prevBlock)
			}
		}
	}
	return prevBlock
}

// BalloonM runs M concurrent Balloon instances and returns
// XOR of their outputs. All other parameters are the same as in Balloon.
func BalloonM(hr func() hash.Hash, passphrase, salt []byte, sCost, tCost uint64, M uint64) []byte {
	out := make([]byte, hr().Size())
	bouts := make(chan []byte)
	for m := uint64(0); m < M; m++ {
		go func(core uint64) {
			binaryM := make([]byte, 8)
			binary.BigEndian.PutUint64(binaryM, core)
			bouts <- Balloon(hr(), passphrase, append(salt, binaryM...), sCost, tCost)
		}(m + 1)
	}
	for m := uint64(0); m < M; m++ {
		for i, v := range <-bouts {
			out[i] ^= v
		}
	}
	return out
}
