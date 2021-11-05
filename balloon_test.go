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

func TestVectors(t *testing.T) {
	type test_vector struct {
		password []byte
		salt []byte
		s_cost uint64
		t_cost uint64
		output string
	}

	test_vectors := []test_vector{
		{
			password: []byte("hunter42"),
			salt: []byte("examplesalt"),
			s_cost: 1024,
			t_cost: 3,
			output: "716043dff777b44aa7b88dcbab12c078abecfac9d289c5b5195967aa63440dfb",
		},
		{
			password: []byte(""),
			salt: []byte("salt"),
			s_cost: 3,
			t_cost: 3,
			output: "5f02f8206f9cd212485c6bdf85527b698956701ad0852106f94b94ee94577378",
		},
		{
			password: []byte("password"),
			salt: []byte(""),
			s_cost: 3,
			t_cost: 3,
			output: "20aa99d7fe3f4df4bd98c655c5480ec98b143107a331fd491deda885c4d6a6cc",
		},
		{
			password: []byte("\000"),
			salt: []byte("\000"),
			s_cost: 3,
			t_cost: 3,
			output: "4fc7e302ffa29ae0eac31166cee7a552d1d71135f4e0da66486fb68a749b73a4",
		},
		{
			password: []byte("password"),
			salt: []byte("salt"),
			s_cost: 1,
			t_cost: 1,
			output: "eefda4a8a75b461fa389c1dcfaf3e9dfacbc26f81f22e6f280d15cc18c417545",
		},
	}

	for _, vector := range test_vectors {
		output := Balloon(sha256.New(), vector.password, vector.salt, vector.s_cost, vector.t_cost)
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
