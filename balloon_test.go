// balloon_test.go - test the Balloon implementation.
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of blake2xb, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package balloon

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"reflect"
	"testing"
)

func BenchmarkBalloon(b *testing.B) {
	ps := make([]byte, 8+8)
	rand.Read(ps)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Balloon(sha512.New(), ps[:8], ps[8:], 16, 16)
	}
}

func BenchmarkBalloonM(b *testing.B) {
	ps := make([]byte, 8+8)
	rand.Read(ps)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BalloonM(sha512.New, ps[:8], ps[8:], 16, 16, 4)
	}
}

func TestBalloonVectors(t *testing.T) {
	type testVector struct {
		password []byte
		salt     []byte
		sCost    uint64
		tCost    uint64
		output   string
	}

	testVectors := []testVector{
		{
			password: []byte("hunter42"),
			salt:     []byte("examplesalt"),
			sCost:    1024,
			tCost:    3,
			output:   "716043dff777b44aa7b88dcbab12c078abecfac9d289c5b5195967aa63440dfb",
		},
		{
			password: []byte(""),
			salt:     []byte("salt"),
			sCost:    3,
			tCost:    3,
			output:   "5f02f8206f9cd212485c6bdf85527b698956701ad0852106f94b94ee94577378",
		},
		{
			password: []byte("password"),
			salt:     []byte(""),
			sCost:    3,
			tCost:    3,
			output:   "20aa99d7fe3f4df4bd98c655c5480ec98b143107a331fd491deda885c4d6a6cc",
		},
		{
			password: []byte("\000"),
			salt:     []byte("\000"),
			sCost:    3,
			tCost:    3,
			output:   "4fc7e302ffa29ae0eac31166cee7a552d1d71135f4e0da66486fb68a749b73a4",
		},
		{
			password: []byte("password"),
			salt:     []byte("salt"),
			sCost:    1,
			tCost:    1,
			output:   "eefda4a8a75b461fa389c1dcfaf3e9dfacbc26f81f22e6f280d15cc18c417545",
		},
	}

	for _, vector := range testVectors {
		output := Balloon(sha256.New(), vector.password, vector.salt, vector.sCost, vector.tCost)
		data, err := hex.DecodeString(vector.output)

		if err != nil {
			panic(err)
		}

		if !reflect.DeepEqual(output, data) {
			t.Log("Expected: ", vector.output, " Output: ", hex.EncodeToString(output))
			t.Fail()
		}
	}
}

func TestBalloonMVectors(t *testing.T) {
	type testVector struct {
		password []byte
		salt     []byte
		sCost    uint64
		tCost    uint64
		pCost    uint64
		output   string
	}

	testVectors := []testVector{
		{
			password: []byte("hunter42"),
			salt:     []byte("examplesalt"),
			sCost:    1024,
			tCost:    3,
			pCost:    4,
			output:   "1832bd8e5cbeba1cb174a13838095e7e66508e9bf04c40178990adbc8ba9eb6f",
		},
		{
			password: []byte(""),
			salt:     []byte("salt"),
			sCost:    3,
			tCost:    3,
			pCost:    2,
			output:   "f8767fe04059cef67b4427cda99bf8bcdd983959dbd399a5e63ea04523716c23",
		},
		{
			password: []byte("password"),
			salt:     []byte(""),
			sCost:    3,
			tCost:    3,
			pCost:    3,
			output:   "bcad257eff3d1090b50276514857e60db5d0ec484129013ef3c88f7d36e438d6",
		},
		{
			password: []byte("password"),
			salt:     []byte(""),
			sCost:    3,
			tCost:    3,
			pCost:    1,
			output:   "498344ee9d31baf82cc93ebb3874fe0b76e164302c1cefa1b63a90a69afb9b4d",
		},
		{
			password: []byte("\000"),
			salt:     []byte("\000"),
			sCost:    3,
			tCost:    3,
			pCost:    4,
			output:   "8a665611e40710ba1fd78c181549c750f17c12e423c11930ce997f04c7153e0c",
		},
		{
			password: []byte("\000"),
			salt:     []byte("\000"),
			sCost:    3,
			tCost:    3,
			pCost:    1,
			output:   "d9e33c683451b21fb3720afbd78bf12518c1d4401fa39f054b052a145c968bb1",
		},
		{
			password: []byte("password"),
			salt:     []byte("salt"),
			sCost:    1,
			tCost:    1,
			pCost:    16,
			output:   "a67b383bb88a282aef595d98697f90820adf64582a4b3627c76b7da3d8bae915",
		},
		{
			password: []byte("password"),
			salt:     []byte("salt"),
			sCost:    1,
			tCost:    1,
			pCost:    1,
			output:   "97a11df9382a788c781929831d409d3599e0b67ab452ef834718114efdcd1c6d",
		},
	}

	for _, vector := range testVectors {
		output := BalloonM(sha256.New, vector.password, vector.salt, vector.sCost, vector.tCost, vector.pCost)
		data, err := hex.DecodeString(vector.output)

		if err != nil {
			panic(err)
		}

		if !reflect.DeepEqual(output, data) {
			t.Log("Expected: ", vector.output, " Output: ", hex.EncodeToString(output))
			t.Fail()
		}
	}
}
