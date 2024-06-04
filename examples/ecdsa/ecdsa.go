package ecdsa

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/backend/witness"
	bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	sig "github.com/consensys/gnark/std/signature/ecdsa"
)

type EcdsaCircuit[T, S emulated.FieldParams] struct {
	Sig sig.Signature[S]
	Msg emulated.Element[S]
	Pub sig.PublicKey[T, S]
}

func (c *EcdsaCircuit[T, S]) Define(api frontend.API) error {
	c.Pub.Verify(api, sw_emulated.GetCurveParams[T](), &c.Msg, &c.Sig)
	return nil
}

func BuildR1CS() (*bn254.R1CS, *witness.Witness, error) {
	// defer the closing of our jsonFile so that we can parse it later on
	privKey, _ := ecdsa.GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (pre-hashed)")
	sigBin, _ := privKey.Sign(msg, nil)

	// check that the signature is correct
	_, err := publicKey.Verify(sigBin, msg, nil)
	if err != nil {
		return nil, nil, err
	}

	// unmarshal signature
	var signature ecdsa.Signature
	signature.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature.R[:32])
	s.SetBytes(signature.S[:32])

	hash := ecdsa.HashToInt(msg)

	// circuit := EcdsaCircuit[emulated.BN254Fp, emulated.BN254Fr]{}
	// w := EcdsaCircuit[emulated.BN254Fp, emulated.BN254Fr]{
	// 	Sig: sig.Signature[emulated.BN254Fr]{
	// 		R: emulated.ValueOf[emulated.BN254Fr](r),
	// 		S: emulated.ValueOf[emulated.BN254Fr](s),
	// 	},
	// 	Msg: emulated.ValueOf[emulated.BN254Fr](hash),
	// 	Pub: sig.PublicKey[emulated.BN254Fp, emulated.BN254Fr]{
	// 		X: emulated.ValueOf[emulated.BN254Fp](privKey.PublicKey.A.X),
	// 		Y: emulated.ValueOf[emulated.BN254Fp](privKey.PublicKey.A.Y),
	// 	},
	// }

	circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	w := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Sig: sig.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
		Pub: sig.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
		},
	}

	err = test.IsSolved(&circuit, &w, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, err
	}

	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	// witness, err := frontend.NewWitness(&w, ecc.SECP256K1.ScalarField())
	if err != nil {
		return nil, nil, err
	}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, err
	}

	return r1cs.(*bn254.R1CS), &witness, err
}
