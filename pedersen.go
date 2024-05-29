package main

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
)

type PedersenKeys struct {
	PK []pedersen.ProvingKey
	VK pedersen.VerifyingKey
}

func (pks *PedersenKeys) Contribute() error {
	var modMinusOne big.Int
	modMinusOne.Sub(fr.Modulus(), big.NewInt(1))
	sigma, err := rand.Int(rand.Reader, &modMinusOne)
	if err != nil {
		return err
	}
	sigma.Add(sigma, big.NewInt(1))

	var sigmaInv big.Int
	sigmaInv.ModInverse(sigma, fr.Modulus())

	pks.VK.GRootSigmaNeg.ScalarMultiplication(&pks.VK.GRootSigmaNeg, &sigmaInv)

	for _, pk := range pks.PK {
		for _, basisExpSigma := range pk.BasisExpSigma {
			basisExpSigma.ScalarMultiplication(&basisExpSigma, sigma)
		}
	}
	pks.VK.GRootSigmaNeg.ScalarMultiplication(&pks.VK.GRootSigmaNeg, &sigmaInv)

	return nil
}

func (pks *PedersenKeys) writeTo(enc *bn254.Encoder) (int64, error) {
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
	return pks.writeTo(bn254.NewEncoder(w))
}

func (pks *PedersenKeys) WriteRawTo(w io.Writer) (int64, error) {
	return pks.writeTo(bn254.NewEncoder(w, bn254.RawEncoding()))
}

func (pks *PedersenKeys) ReadFrom(r io.Reader) (int64, error) {
	dec := bn254.NewDecoder(r)

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

func randomOnG2() (bn254.G2Affine, error) { // TODO: Add to G2.go?
	if gBytes, err := randomFrSizedBytes(); err != nil {
		return bn254.G2Affine{}, err
	} else {
		return bn254.HashToG2(gBytes, []byte("random on g2"))
	}
}

func Setup(bases ...[]bn254.G1Affine) (pk []pedersen.ProvingKey, vk pedersen.VerifyingKey, err error) {
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
		pk[i].BasisExpSigma = make([]bn254.G1Affine, len(bases[i]))
		for j := range bases[i] {
			pk[i].BasisExpSigma[j].ScalarMultiplication(&bases[i][j], sigma)
		}
		pk[i].Basis = bases[i]
	}
	return
}
