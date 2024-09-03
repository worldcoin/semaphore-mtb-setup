package main

import (
	"crypto/rand"
	"io"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
)

type PedersenKeys struct {
	PK []pedersen.ProvingKey
	VK pedersen.VerifyingKey
}

func InitPedersen(bases ...[]curve.G1Affine) (pks PedersenKeys, err error) {
	_, _, _, g2 := curve.Generators()

	pks.VK.G = g2

	var modMinusOne big.Int
	modMinusOne.Sub(fr.Modulus(), big.NewInt(1))

	// set sigma to 1
	sigma := big.NewInt(1)

	// Todo: simplify
	var sigmaInvNeg big.Int
	sigmaInvNeg.ModInverse(sigma, fr.Modulus())
	sigmaInvNeg.Sub(fr.Modulus(), &sigmaInvNeg)
	pks.VK.GRootSigmaNeg.ScalarMultiplication(&pks.VK.G, &sigmaInvNeg)

	pks.PK = make([]pedersen.ProvingKey, len(bases))
	for i := range bases {
		pks.PK[i].BasisExpSigma = make([]curve.G1Affine, len(bases[i]))
		for j := range bases[i] {
			pks.PK[i].BasisExpSigma[j].ScalarMultiplication(&bases[i][j], sigma)
		}
		pks.PK[i].Basis = bases[i]
	}
	return
}

func (pks *PedersenKeys) Contribute() error {
	var sigma, sigmaInv fr.Element
	var sigmaBI, sigmaInvBI big.Int
	sigma.SetRandom()
	sigmaInv.Inverse(&sigma)

	sigma.BigInt(&sigmaBI)
	sigmaInv.BigInt(&sigmaInvBI)

	pks.VK.GRootSigmaNeg.ScalarMultiplication(&pks.VK.GRootSigmaNeg, &sigmaInvBI)

	for _, pk := range pks.PK {
		for i := range pk.BasisExpSigma {
			pk.BasisExpSigma[i].ScalarMultiplication(&pk.BasisExpSigma[i], &sigmaBI)
		}
	}

	return nil
}

func (pks *PedersenKeys) writeTo(enc *curve.Encoder) (int64, error) {
	for _, pk := range pks.PK {
		if err := enc.Encode(pk.Basis); err != nil {
			return enc.BytesWritten(), err
		}

		if err := enc.Encode(pk.BasisExpSigma); err != nil {
			return enc.BytesWritten(), err
		}
	}

	if err := enc.Encode(&pks.VK.G); err != nil {
		return enc.BytesWritten(), err
	}
	err := enc.Encode(&pks.VK.GRootSigmaNeg)

	return enc.BytesWritten(), err
}

func (pks *PedersenKeys) WriteTo(w io.Writer) (int64, error) {
	return pks.writeTo(curve.NewEncoder(w))
}

func (pks *PedersenKeys) WriteRawTo(w io.Writer) (int64, error) {
	return pks.writeTo(curve.NewEncoder(w, curve.RawEncoding()))
}

func (pks *PedersenKeys) ReadFrom(r io.Reader) (int64, error) {
	dec := curve.NewDecoder(r)

	if err := dec.Decode(&pks.PK); err != nil {
		return dec.BytesRead(), err
	}
	if err := dec.Decode(&pks.VK); err != nil {
		return dec.BytesRead(), err
	}

	return dec.BytesRead(), nil
}

func randomFrSizedBytes() ([]byte, error) {
	res := make([]byte, fr.Bytes)
	_, err := rand.Read(res)
	return res, err
}

func randomOnG2() (curve.G2Affine, error) { // TODO: Add to G2.go?
	if gBytes, err := randomFrSizedBytes(); err != nil {
		return curve.G2Affine{}, err
	} else {
		return curve.HashToG2(gBytes, []byte("random on g2"))
	}
}

func Setup(bases ...[]curve.G1Affine) (pk []pedersen.ProvingKey, vk pedersen.VerifyingKey, err error) {
	if vk.G, err = randomOnG2(); err != nil {
		return
	}

	var modMinusOne big.Int
	modMinusOne.Sub(fr.Modulus(), big.NewInt(1))
	var sigma *big.Int
	if sigma, err = rand.Int(rand.Reader, &modMinusOne); err != nil {
		return
	}
	sigma.Add(sigma, big.NewInt(1))

	var sigmaInvNeg big.Int
	sigmaInvNeg.ModInverse(sigma, fr.Modulus())
	sigmaInvNeg.Sub(fr.Modulus(), &sigmaInvNeg)
	vk.GRootSigmaNeg.ScalarMultiplication(&vk.G, &sigmaInvNeg)

	pk = make([]pedersen.ProvingKey, len(bases))
	for i := range bases {
		pk[i].BasisExpSigma = make([]curve.G1Affine, len(bases[i]))
		for j := range bases[i] {
			pk[i].BasisExpSigma[j].ScalarMultiplication(&bases[i][j], sigma)
		}
		pk[i].Basis = bases[i]
	}
	return
}
