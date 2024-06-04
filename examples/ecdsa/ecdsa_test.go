package ecdsa

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"

	"github.com/consensys/gnark/std/math/emulated"
	da "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
)

func TestEcdsaSHA256(t *testing.T) {
	// generate parameters
	privKey, _ := ecdsa.GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (sha256)")
	md := sha256.New()
	sigBin, _ := privKey.Sign(msg, md)

	// check that the signature is correct
	flag, _ := publicKey.Verify(sigBin, msg, md)
	if !flag {
		t.Errorf("can't verify signature")
	}

	// unmarshal signature
	var sig ecdsa.Signature
	sig.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])

	// compute the hash of the message as an integer
	dataToHash := make([]byte, len(msg))
	copy(dataToHash[:], msg[:])
	md.Reset()
	md.Write(dataToHash[:])
	hramBin := md.Sum(nil)
	hash := ecdsa.HashToInt(hramBin)

	circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Sig: da.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
		Pub: da.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
		},
	}
	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
