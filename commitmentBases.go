package main

import (
	"errors"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
)

func InitCommitmentBases(r1cs *cs.R1CS, evals *mpcsetup.Phase2Evaluations) ([][]curve.G1Affine, error) {
	/*
		Setup
		-----
		To build the verifying keys:
		- compile the r1cs system -> the number of gates is len(GateOrdering)+len(PureStructuralConstraints)+len(InpureStructuralConstraints)
		- loop through the ordered computational constraints (=gate in r1cs system structure), eValuate A(X), B(X), C(X) with simple formula (the gate number is the current iterator)
		- loop through the inpure structural constraints, eValuate A(X), B(X), C(X) with simple formula, the gate number is len(gateOrdering)+ current iterator
		- loop through the pure structural constraints, eValuate A(X), B(X), C(X) with simple formula, the gate number is len(gateOrdering)+len(InpureStructuralConstraints)+current iterator
	*/

	// get R1CS nb constraints, wires and public/private inputs
	// nbWires := r1cs.NbInternalVariables + r1cs.GetNbPublicVariables() + r1cs.GetNbSecretVariables()

	commitmentInfo := r1cs.CommitmentInfo.(constraint.Groth16Commitments)
	commitmentWires := commitmentInfo.CommitmentIndexes()
	privateCommitted := commitmentInfo.GetPrivateCommitted()
	nbPrivateCommittedWires := NbElements(privateCommitted)

	// a commitment is itself defined by a hint so the prover considers it private
	// but the verifier will need to inject the value itself so on the groth16
	// level it must be considered public
	nbPublicWires := r1cs.GetNbPublicVariables() + len(commitmentInfo)
	nbPrivateWires := r1cs.GetNbSecretVariables() + r1cs.NbInternalVariables - nbPrivateCommittedWires - len(commitmentInfo)

	// Setting group for fft
	domain := fft.NewDomain(uint64(r1cs.GetNbConstraints()))

	// samples toxic waste
	toxicWaste, err := sampleToxicWaste()
	if err != nil {
		return nil, err
	}

	// Setup coeffs to compute pk.G1.A, pk.G1.B, pk.G1.K
	A, B, C := setupABC(r1cs, domain, toxicWaste)

	// To fill in the Proving and Verifying keys, we need to perform a lot of ecc scalar multiplication (with generator)
	// and convert the resulting points to affine
	// this is done using the curve.BatchScalarMultiplicationGX API, which takes as input the base point
	// (in our case the generator) and the list of scalars, and outputs a list of points (len(points) == len(scalars))
	// to use this batch call, we need to order our scalars in the same slice
	// we have 1 batch call for G1 and 1 batch call for G1
	// scalars are fr.Element in non montgomery form
	_, _, g1, _ := curve.Generators()

	// ---------------------------------------------------------------------------------------------
	// G1 scalars

	// the G1 scalars are ordered (arbitrary) as follows:
	//
	// [[α], [β], [δ], [A(i)], [B(i)], [pk.K(i)], [Z(i)], [vk.K(i)]]
	// len(A) == len(B) == nbWires
	// len(pk.K) == nbPrivateWires
	// len(vk.K) == nbPublicWires
	// len(Z) == domain.Cardinality

	// compute scalars for pkK, vkK and ckK
	pkK := make([]fr.Element, nbPrivateWires)
	vkK := make([]fr.Element, nbPublicWires)
	ckK := make([][]fr.Element, len(commitmentInfo))
	ckKLen := 0
	for i := range commitmentInfo {
		len := len(privateCommitted[i])
		ckKLen += len
		ckK[i] = make([]fr.Element, len)
	}

	var t0, t1 fr.Element

	computeK := func(i int, coeff *fr.Element) { // TODO: Inline again
		t1.Mul(&A[i], &toxicWaste.beta)
		t0.Mul(&B[i], &toxicWaste.alpha)
		t1.Add(&t1, &t0).
			Add(&t1, &C[i]).
			Mul(&t1, coeff)
	}
	vI := 0                                // number of public wires seen so far
	cI := make([]int, len(commitmentInfo)) // number of private committed wires seen so far for each commitment
	nbPrivateCommittedSeen := 0            // = ∑ᵢ cI[i]
	nbCommitmentsSeen := 0

	for i := range A {
		commitment := -1 // index of the commitment that commits to this variable as a private or commitment value
		var isCommitment, isPublic bool
		if isPublic = i < r1cs.GetNbPublicVariables(); !isPublic {
			if nbCommitmentsSeen < len(commitmentWires) && commitmentWires[nbCommitmentsSeen] == i {
				isCommitment = true
				nbCommitmentsSeen++
			}

			for j := range commitmentInfo { // does commitment j commit to i?
				if cI[j] < len(privateCommitted[j]) && privateCommitted[j][cI[j]] == i {
					commitment = j
					break // frontend guarantees that no private variable is committed to more than once
				}
			}
		}

		if isPublic || commitment != -1 || isCommitment {
			computeK(i, &toxicWaste.gammaInv)

			if isPublic || isCommitment {
				vkK[vI] = t1
				vI++
			} else { // committed and private
				ckK[commitment][cI[commitment]] = t1
				cI[commitment]++
				nbPrivateCommittedSeen++
			}
		} else {
			computeK(i, &toxicWaste.deltaInv)
			pkK[i-vI-nbPrivateCommittedSeen] = t1 // vI = nbPublicSeen + nbCommitmentsSeen
		}
	}

	// // Z part of the proving key (scalars)
	// Z := make([]fr.Element, domain.Cardinality)
	// one := fr.One()
	// var zdt fr.Element
	//
	// zdt.Exp(toxicWaste.t, new(big.Int).SetUint64(domain.Cardinality)).
	// 	Sub(&zdt, &one).
	// 	Mul(&zdt, &toxicWaste.deltaInv) // sets Zdt to Zdt/delta
	//
	// for i := 0; i < int(domain.Cardinality); i++ {
	// 	Z[i] = zdt
	// 	zdt.Mul(&zdt, &toxicWaste.t)
	// }
	//
	// // mark points at infinity and filter them
	// pk.InfinityA = make([]bool, len(A))
	// pk.InfinityB = make([]bool, len(B))
	//
	// n := 0
	// for i, e := range A {
	// 	if e.IsZero() {
	// 		pk.InfinityA[i] = true
	// 		continue
	// 	}
	// 	A[n] = A[i]
	// 	n++
	// }
	// A = A[:n]
	// pk.NbInfinityA = uint64(nbWires - n)
	// n = 0
	// for i, e := range B {
	// 	if e.IsZero() {
	// 		pk.InfinityB[i] = true
	// 		continue
	// 	}
	// 	B[n] = B[i]
	// 	n++
	// }
	// B = B[:n]
	// pk.NbInfinityB = uint64(nbWires - n)
	//
	// // compute our batch scalar multiplication with g1 elements
	g1Scalars := make([]fr.Element, 0, ckKLen)
	// g1Scalars = append(g1Scalars, toxicWaste.alpha, toxicWaste.beta, toxicWaste.delta)
	// g1Scalars = append(g1Scalars, A...)
	// g1Scalars = append(g1Scalars, B...)
	// g1Scalars = append(g1Scalars, Z...)
	// g1Scalars = append(g1Scalars, vkK...)
	// g1Scalars = append(g1Scalars, pkK...)
	for i := range ckK {
		g1Scalars = append(g1Scalars, ckK[i]...)
	}

	g1PointsAff := curve.BatchScalarMultiplicationG1(&g1, g1Scalars)
	offset := 0

	// // sets pk: [α]₁, [β]₁, [δ]₁
	// pk.G1.Alpha = g1PointsAff[0]
	// pk.G1.Beta = g1PointsAff[1]
	// pk.G1.Delta = g1PointsAff[2]
	//
	// offset := 3
	// pk.G1.A = g1PointsAff[offset : offset+len(A)]
	// offset += len(A)
	//
	// pk.G1.B = g1PointsAff[offset : offset+len(B)]
	// offset += len(B)
	//
	// bitReverse(g1PointsAff[offset : offset+int(domain.Cardinality)])
	// sizeZ := int(domain.Cardinality) - 1 // deg(H)=deg(A*B-C/X^n-1)=(n-1)+(n-1)-n=n-2
	// pk.G1.Z = g1PointsAff[offset : offset+sizeZ]
	//
	// offset += int(domain.Cardinality)
	//
	// vk.G1.K = g1PointsAff[offset : offset+nbPublicWires]
	// offset += nbPublicWires
	//
	// pk.G1.K = g1PointsAff[offset : offset+nbPrivateWires]
	// offset += nbPrivateWires

	// ---------------------------------------------------------------------------------------------
	// Commitment setup

	commitmentBases := make([][]curve.G1Affine, len(commitmentInfo))
	for i := range commitmentBases {
		size := len(ckK[i])
		commitmentBases[i] = g1PointsAff[offset : offset+size]
		offset += size
	}
	if offset != len(g1PointsAff) {
		return nil, errors.New("didn't consume all G1 points") // TODO @Tabaie Remove this
	}

	return commitmentBases, nil
}

func setupABC(r1cs *cs.R1CS, domain *fft.Domain, toxicWaste toxicWaste) (A []fr.Element, B []fr.Element, C []fr.Element) {
	nbWires := r1cs.NbInternalVariables + r1cs.GetNbPublicVariables() + r1cs.GetNbSecretVariables()

	A = make([]fr.Element, nbWires)
	B = make([]fr.Element, nbWires)
	C = make([]fr.Element, nbWires)

	one := fr.One()

	// first we compute [t-w^i] and its inverse
	var w fr.Element
	w.Set(&domain.Generator)
	wi := fr.One()
	t := make([]fr.Element, r1cs.GetNbConstraints()+1)
	for i := 0; i < len(t); i++ {
		t[i].Sub(&toxicWaste.t, &wi)
		wi.Mul(&wi, &w) // TODO this is already pre computed in fft.Domain
	}
	tInv := fr.BatchInvert(t)

	// evaluation of the i-th lagrange polynomial at t
	var L fr.Element

	// L = 1/n*(t^n-1)/(t-1), Li+1 = w*Li*(t-w^i)/(t-w^(i+1))

	// Setting L0
	L.Exp(toxicWaste.t, new(big.Int).SetUint64(uint64(domain.Cardinality))).
		Sub(&L, &one)
	L.Mul(&L, &tInv[0]).
		Mul(&L, &domain.CardinalityInv)

	accumulate := func(res *fr.Element, t constraint.Term, value *fr.Element) {
		cID := t.CoeffID()
		switch cID {
		case constraint.CoeffIdZero:
			return
		case constraint.CoeffIdOne:
			res.Add(res, value)
		case constraint.CoeffIdMinusOne:
			res.Sub(res, value)
		case constraint.CoeffIdTwo:
			var buffer fr.Element
			buffer.Double(value)
			res.Add(res, &buffer)
		default:
			var buffer fr.Element
			buffer.Mul(&r1cs.Coefficients[cID], value)
			res.Add(res, &buffer)
		}
	}

	// each constraint is in the form
	// L * R == O
	// L, R and O being linear expressions
	// for each term appearing in the linear expression,
	// we compute term.Coefficient * L, and cumulate it in
	// A, B or C at the index of the variable

	j := 0
	it := r1cs.GetR1CIterator()
	for c := it.Next(); c != nil; c = it.Next() {
		for _, t := range c.L {
			accumulate(&A[t.WireID()], t, &L)
		}
		for _, t := range c.R {
			accumulate(&B[t.WireID()], t, &L)
		}
		for _, t := range c.O {
			accumulate(&C[t.WireID()], t, &L)
		}

		// Li+1 = w*Li*(t-w^i)/(t-w^(i+1))
		L.Mul(&L, &w)
		L.Mul(&L, &t[j])
		L.Mul(&L, &tInv[j+1])

		j++
	}

	return
}

// toxicWaste toxic waste
type toxicWaste struct {
	// Montgomery form of params
	t, alpha, beta, gamma, delta fr.Element
	gammaInv, deltaInv           fr.Element
}

func sampleToxicWaste() (toxicWaste, error) {
	res := toxicWaste{}

	for res.t.IsZero() {
		if _, err := res.t.SetRandom(); err != nil {
			return res, err
		}
	}
	for res.alpha.IsZero() {
		if _, err := res.alpha.SetRandom(); err != nil {
			return res, err
		}
	}
	for res.beta.IsZero() {
		if _, err := res.beta.SetRandom(); err != nil {
			return res, err
		}
	}
	for res.gamma.IsZero() {
		if _, err := res.gamma.SetRandom(); err != nil {
			return res, err
		}
	}
	for res.delta.IsZero() {
		if _, err := res.delta.SetRandom(); err != nil {
			return res, err
		}
	}

	res.gammaInv.Inverse(&res.gamma)
	res.deltaInv.Inverse(&res.delta)

	return res, nil
}

func ConcatAll(slices ...[]int) []int { // copyright note: written by GitHub Copilot
	totalLen := 0
	for _, s := range slices {
		totalLen += len(s)
	}
	res := make([]int, totalLen)
	i := 0
	for _, s := range slices {
		i += copy(res[i:], s)
	}
	return res
}

func NbElements(slices [][]int) int { // copyright note: written by GitHub Copilot
	totalLen := 0
	for _, s := range slices {
		totalLen += len(s)
	}
	return totalLen
}
