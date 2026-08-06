package phase2

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/worldcoin/semaphore-mtb-setup/common"
	"github.com/worldcoin/semaphore-mtb-setup/phase1"
)

func nextPowerofTwo(number int) int {
	res := 2
	for i := 1; i < 28; i++ { // max power is 28
		if res >= number {
			return res
		} else {
			res *= 2
		}
	}
	// Shouldn't happen
	panic("the power is beyond 28")
}

func processHeader(r1csPath string, phase1File, phase2File *os.File) (*phase1.Header, *Header, error) {
	fmt.Println("Processing the headers ...")

	var header2 Header
	var header1 phase1.Header

	// Read the #Constraints
	r1csFile, err := os.Open(r1csPath)
	if err != nil {
		return nil, nil, err
	}
	defer r1csFile.Close()
	var r1cs cs_bn254.R1CS
	if _, err := r1cs.ReadFrom(r1csFile); err != nil {
		return nil, nil, err
	}
	header2.Constraints = r1cs.GetNbConstraints()
	header2.Domain = nextPowerofTwo(header2.Constraints)

	// Check if phase 1 power can support the current #Constraints
	if err := header1.ReadFrom(phase1File); err != nil {
		return nil, nil, err
	}
	N := int(math.Pow(2, float64(header1.Power)))
	if N < header2.Constraints {
		return nil, nil, fmt.Errorf("phase 1 parameters can support up to %d, but the circuit #Constraints are %d", N, header2.Constraints)
	}
	// Initialize Domain, #Wires, #Witness, #Public, #PrivateCommitted

	// Calculate number of private commitments
	commitments, ok := r1cs.CommitmentInfo.(constraint.Groth16Commitments)
	if !ok {
		return nil, nil, errors.New("commitment info is not of type Groth16Commitments")
	}
	privateCommittedNum := 0
	for _, commitment := range commitments {
		privateCommittedNum += len(commitment.PrivateCommitted)
	}

	header2.Wires = r1cs.NbInternalVariables + r1cs.GetNbPublicVariables() + r1cs.GetNbSecretVariables()
	header2.PrivateCommitted = privateCommittedNum
	header2.Public = r1cs.GetNbPublicVariables()
	header2.Witness = r1cs.GetNbSecretVariables() + r1cs.NbInternalVariables - header2.PrivateCommitted

	if Is(commitments) { // the commitment itself is defined by a hint so the prover considers it private
		header2.Public++  // but the verifier will need to inject the value itself so on the groth16
		header2.Witness-- // level it must be considered public
	}

	// Write header of phase 2
	if err := header2.write(phase2File); err != nil {
		return nil, nil, err
	}
	fmt.Printf("Circuit Info: #Constraints:=%d\n#Wires:=%d\n#Public:=%d\n#Witness:=%d\n#PrivateCommitted:=%d\n",
		header2.Constraints, header2.Wires, header2.Public, header2.Witness, header2.PrivateCommitted)
	return &header1, &header2, nil
}

func processLagrange(header1 *phase1.Header, header2 *Header, phase1File, phase2File *os.File) error {
	fmt.Println("Converting to Lagrange basis ...")
	domain := fft.NewDomain(uint64(header2.Domain))
	N := int(math.Pow(2, float64(header1.Power)))

	lagFile, err := os.Create("srs.lag")
	if err != nil {
		return err
	}
	defer lagFile.Close()

	// TauG1
	fmt.Println("Converting TauG1")
	pos := int64(3)
	if err := lagrangeG1(phase1File, lagFile, pos, domain); err != nil {
		return err
	}
	// AlphaTauG1
	fmt.Println("Converting AlphaTauG1")
	pos += 32 * (2*int64(N) - 1)
	if err := lagrangeG1(phase1File, lagFile, pos, domain); err != nil {
		return err
	}

	// BetaTauG1
	fmt.Println("Converting BetaTauG1")
	pos += 32 * int64(N)
	if err := lagrangeG1(phase1File, lagFile, pos, domain); err != nil {
		return err
	}

	// TauG2
	fmt.Println("Converting TauG2")
	pos += 32 * int64(N)
	if err := lagrangeG2(phase1File, lagFile, pos, domain); err != nil {
		return err
	}

	return nil
}

func processEvaluations(header1 *phase1.Header, header2 *Header, r1csPath string, phase1File *os.File) error {
	fmt.Println("Processing evaluation of [A]₁, [B]₁, [B]₂")

	lagFile, err := os.Open("srs.lag")
	if err != nil {
		return err
	}
	defer lagFile.Close()

	evalFile, err := os.Create("evals")
	if err != nil {
		return err
	}
	defer evalFile.Close()

	// Read [α]₁ , [β]₁ , [β]₂  from phase1 (Check Phase 1 file format for reference)
	alpha, beta1, beta2, err := readPhase1(phase1File, header1.Power)
	if err != nil {
		return err
	}

	// Write [α]₁ , [β]₁ , [β]₂
	enc := bn254.NewEncoder(evalFile)
	if err := enc.Encode(alpha); err != nil {
		return err
	}
	if err := enc.Encode(beta1); err != nil {
		return err
	}
	if err := enc.Encode(beta2); err != nil {
		return err
	}

	var tauG1 []bn254.G1Affine

	// Read R1CS File
	r1csFile, err := os.Open(r1csPath)
	if err != nil {
		return err
	}
	defer r1csFile.Close()
	var r1cs cs_bn254.R1CS
	if _, err := r1cs.ReadFrom(r1csFile); err != nil {
		return err
	}

	// Deserialize Lagrange SRS TauG1
	dec := bn254.NewDecoder(lagFile)
	if err := dec.Decode(&tauG1); err != nil {
		return err
	}

	// Accumlate {[A]₁}
	buff := make([]bn254.G1Affine, header2.Wires)
	for i, c := range r1cs.GetR1Cs() {
		for _, t := range c.L {
			accumulateG1(&r1cs, &buff[t.WireID()], t, &tauG1[i])
		}
	}
	// Serialize {[A]₁}
	if err := enc.Encode(buff); err != nil {
		return err
	}

	// Reset buff
	buff = make([]bn254.G1Affine, header2.Wires)
	// Accumlate {[B]₁}
	for i, c := range r1cs.GetR1Cs() {
		for _, t := range c.R {
			accumulateG1(&r1cs, &buff[t.WireID()], t, &tauG1[i])
		}
	}
	// Serialize {[B]₁}
	if err := enc.Encode(buff); err != nil {
		return err
	}

	var tauG2 []bn254.G2Affine
	buff2 := make([]bn254.G2Affine, header2.Wires)

	// Seek to Lagrange SRS TauG2 by skipping AlphaTau and BetaTau
	pos := 2*32*int64(header2.Domain) + 2*4
	if _, err := lagFile.Seek(pos, io.SeekCurrent); err != nil {
		return err
	}

	// Deserialize Lagrange SRS TauG2
	if err := dec.Decode(&tauG2); err != nil {
		return err
	}
	// Accumlate {[B]₂}
	for i, c := range r1cs.GetR1Cs() {
		for _, t := range c.R {
			accumulateG2(&r1cs, &buff2[t.WireID()], t, &tauG2[i])
		}
	}
	// Serialize {[B]₂}
	if err := enc.Encode(buff2); err != nil {
		return err
	}

	return nil
}

func processDeltaAndZ(header1 *phase1.Header, header2 *Header, phase1File, phase2File *os.File) error {
	fmt.Println("Processing Delta and Z")
	writer := bufio.NewWriter(phase2File)
	defer writer.Flush()
	enc := bn254.NewEncoder(writer)

	// Write [δ]₁ and [δ]₂
	_, _, g1, g2 := bn254.Generators()
	if err := enc.Encode(&g1); err != nil {
		return err
	}
	if err := enc.Encode(&g2); err != nil {
		return err
	}

	// Seek to TauG1
	var pos int64 = 3
	if _, err := phase1File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReader(phase1File)
	dec := bn254.NewDecoder(reader)

	n := header2.Domain
	tauG1 := make([]bn254.G1Affine, 2*n-1)
	for i := 0; i < len(tauG1); i++ {
		if err := dec.Decode(&tauG1[i]); err != nil {
			return err
		}
	}

	// Calculate Z
	Z := make([]bn254.G1Affine, n)
	for i := 0; i < n-1; i++ {
		Z[i].Sub(&tauG1[i+n], &tauG1[i])
	}
	common.BitReverseG1(Z)

	// Write Z
	for i := 0; i < len(Z); i++ {
		if err := enc.Encode(&Z[i]); err != nil {
			return err
		}
	}
	return nil
}

func processPVCKK(header1 *phase1.Header, header2 *Header, r1csPath string, phase2File *os.File) error {
	fmt.Println("Processing PKK, VKK, and CKK")
	lagFile, err := os.Open("srs.lag")
	if err != nil {
		return err
	}
	defer lagFile.Close()

	// Read R1CS File
	r1csFile, err := os.Open(r1csPath)
	if err != nil {
		return err
	}
	defer r1csFile.Close()
	var r1cs cs_bn254.R1CS
	if _, err := r1cs.ReadFrom(r1csFile); err != nil {
		return err
	}

	var buffSRS []bn254.G1Affine
	reader := bufio.NewReader(lagFile)
	writer := bufio.NewWriter(phase2File)
	defer writer.Flush()
	dec := bn254.NewDecoder(reader)
	enc := bn254.NewEncoder(writer)

	// L = O(TauG1) + R(AlphaTauG1) + L(BetaTauG1)
	L := make([]bn254.G1Affine, header2.Wires)

	// Deserialize Lagrange SRS TauG1
	if err := dec.Decode(&buffSRS); err != nil {
		return err
	}

	for i, c := range r1cs.GetR1Cs() {
		// Output(Tau)
		for _, t := range c.O {
			accumulateG1(&r1cs, &L[t.WireID()], t, &buffSRS[i])
		}
	}

	// Deserialize Lagrange SRS AlphaTauG1
	if err := dec.Decode(&buffSRS); err != nil {
		return err
	}
	for i, c := range r1cs.GetR1Cs() {
		// Right(AlphaTauG1)
		for _, t := range c.R {
			accumulateG1(&r1cs, &L[t.WireID()], t, &buffSRS[i])
		}
	}

	// Deserialize Lagrange SRS BetaTauG1
	if err := dec.Decode(&buffSRS); err != nil {
		return err
	}
	for i, c := range r1cs.GetR1Cs() {
		// Left(BetaTauG1)
		for _, t := range c.L {
			accumulateG1(&r1cs, &L[t.WireID()], t, &buffSRS[i])
		}
	}

	commitments, ok := r1cs.CommitmentInfo.(constraint.Groth16Commitments)
	if !ok {
		return errors.New("commitment info is not of type Groth16Commitments")
	}

	pkk, vkk, ckk := filterL(L, header2, commitments)
	// Write PKK
	for i := 0; i < len(pkk); i++ {
		if err := enc.Encode(&pkk[i]); err != nil {
			return err
		}
	}

	// VKK
	evalFile, err := os.OpenFile("evals", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer evalFile.Close()
	evalWriter := bufio.NewWriter(evalFile)
	defer evalWriter.Flush()
	evalEnc := bn254.NewEncoder(evalWriter)
	if err := evalEnc.Encode(vkk); err != nil {
		return err
	}

	// Write CKK
	if err := evalEnc.Encode(ckk); err != nil {
		return err
	}

	// Write CommitmentInfo
	cmtEnc := gob.NewEncoder(evalWriter)
	if err := cmtEnc.Encode(r1cs.CommitmentInfo); err != nil {
		return err
	}

	return nil
}

func accumulateG1(r1cs *cs_bn254.R1CS, res *bn254.G1Affine, t constraint.Term, value *bn254.G1Affine) {
	cID := t.CoeffID()
	switch cID {
	case constraint.CoeffIdZero:
		return
	case constraint.CoeffIdOne:
		res.Add(res, value)
	case constraint.CoeffIdMinusOne:
		res.Sub(res, value)
	case constraint.CoeffIdTwo:
		res.Add(res, value).Add(res, value)
	default:
		var tmp bn254.G1Affine
		var vBi big.Int
		r1cs.Coefficients[cID].BigInt(&vBi)
		tmp.ScalarMultiplication(value, &vBi)
		res.Add(res, &tmp)
	}
}

func accumulateG2(r1cs *cs_bn254.R1CS, res *bn254.G2Affine, t constraint.Term, value *bn254.G2Affine) {
	cID := t.CoeffID()
	switch cID {
	case constraint.CoeffIdZero:
		return
	case constraint.CoeffIdOne:
		res.Add(res, value)
	case constraint.CoeffIdMinusOne:
		res.Sub(res, value)
	case constraint.CoeffIdTwo:
		res.Add(res, value).Add(res, value)
	default:
		var tmp bn254.G2Affine
		var vBi big.Int
		r1cs.Coefficients[cID].BigInt(&vBi)
		tmp.ScalarMultiplication(value, &vBi)
		res.Add(res, &tmp)
	}
}

func scale(dec *bn254.Decoder, enc *bn254.Encoder, N int, delta *big.Int) error {
	// Allocate batch with smallest of (N, batchSize)
	const batchSize = 1048576 // 2^20
	var initialSize = int(math.Min(float64(N), float64(batchSize)))
	buff := make([]bn254.G1Affine, initialSize)

	remaining := N
	for remaining > 0 {
		// Read batch
		readCount := int(math.Min(float64(remaining), float64(batchSize)))
		for i := 0; i < readCount; i++ {
			if err := dec.Decode(&buff[i]); err != nil {
				return err
			}
		}

		// Process the batch
		common.Parallelize(readCount, func(start, end int) {
			for i := start; i < end; i++ {
				buff[i].ScalarMultiplication(&buff[i], delta)
			}
		})

		// Write batch
		for i := 0; i < readCount; i++ {
			if err := enc.Encode(&buff[i]); err != nil {
				return err
			}
		}

		// Update remaining
		remaining -= readCount
	}

	return nil
}

func verifyContribution(c *Contribution, prevDelta bn254.G1Affine, prevHash []byte) error {
	// Compute SP for δ
	deltaSP := common.GenSP(c.PublicKey.S, c.PublicKey.SX, prevHash, 1)

	// Check for knowledge of δ
	if !common.SameRatio(c.PublicKey.S, c.PublicKey.SX, c.PublicKey.SPX, deltaSP) {
		return errors.New("couldn't verify knowledge of Delta")
	}

	// Check for valid update δ using previous parameters
	if !common.SameRatio(c.Delta, prevDelta, deltaSP, c.PublicKey.SPX) {
		return errors.New("couldn't verify that [δ]₁ is based on previous contribution")
	}
	// Verify contribution hash
	b := computeHash(c)
	if !bytes.Equal(c.Hash, b) {
		return fmt.Errorf("contribution hash is invalid")
	}

	return nil
}

func verifyParameter(delta, g *bn254.G2Affine, inputDecoder, originDecoder *bn254.Decoder, size int, field string) error {
	// aggregate points
	if in, or, err := aggregate(inputDecoder, originDecoder, size); err != nil {
		return nil
	} else {
		if !common.SameRatio(*in, *or, *delta, *g) {
			return fmt.Errorf("inconsistent update to %s", field)
		}
	}
	return nil
}

func aggregate(inputDecoder, originDecoder *bn254.Decoder, size int) (*bn254.G1Affine, *bn254.G1Affine, error) {
	var inG, orG, tmp bn254.G1Affine
	// Allocate batch with smallest of (N, batchSize)
	const batchSize = 1048576 // 2^20
	var initialSize = int(math.Min(float64(size), float64(batchSize)))
	buff := make([]bn254.G1Affine, initialSize)
	r := make([]fr.Element, size)

	remaining := size
	for remaining > 0 {

		// generate randomness
		common.Parallelize(len(r), func(start, end int) {
			for i := start; i < end; i++ {
				r[i].SetRandom()
			}
		})

		// Read from input
		readCount := int(math.Min(float64(remaining), float64(batchSize)))
		for i := 0; i < readCount; i++ {
			if err := inputDecoder.Decode(&buff[i]); err != nil {
				return nil, nil, err
			}
		}

		// Aggregate input
		if _, err := tmp.MultiExp(buff[:readCount], r[:readCount], ecc.MultiExpConfig{}); err != nil {
			return nil, nil, err
		}
		inG.Add(&inG, &tmp)

		// Read from origin
		for i := 0; i < readCount; i++ {
			if err := originDecoder.Decode(&buff[i]); err != nil {
				return nil, nil, err
			}
		}

		// Aggregate origin
		if _, err := tmp.MultiExp(buff[:readCount], r[:readCount], ecc.MultiExpConfig{}); err != nil {
			return nil, nil, err
		}
		orG.Add(&orG, &tmp)

		// Update remaining
		remaining -= readCount
	}

	return &inG, &orG, nil
}

func filterL(L []bn254.G1Affine, header2 *Header, cmtInfo constraint.Groth16Commitments) ([]bn254.G1Affine, []bn254.G1Affine, []bn254.G1Affine) {
	pkk := make([]bn254.G1Affine, header2.Witness)
	vkk := make([]bn254.G1Affine, header2.Public)
	ckk := make([]bn254.G1Affine, header2.PrivateCommitted)
	vI, cI := 0, 0

	commitmentIndexes := make(map[int]struct{})
	for _, c := range cmtInfo {
		commitmentIndexes[c.CommitmentIndex] = struct{}{}
	}

	numPrivateCommitted := 0
	for _, commitment := range cmtInfo {
		numPrivateCommitted += len(commitment.PrivateCommitted)
	}

	for i := range L {
		_, isCommitment := commitmentIndexes[i]
		isCommittedPrivate := cI < numPrivateCommitted
		isPublic := i < header2.Public

		if isCommittedPrivate {
			if cI < len(ckk) {
				ckk[cI].Set(&L[i])
				cI++
			}
		} else if isCommitment || isPublic {
			if vI < len(vkk) {
				vkk[vI].Set(&L[i])
				vI++
			}
		} else {
			pIndex := i - cI - vI
			if pIndex >= 0 && pIndex < len(pkk) {
				pkk[pIndex].Set(&L[i])
			}
		}
	}

	return pkk, vkk, ckk
}

func readPhase1(phase1File *os.File, power byte) (*bn254.G1Affine, *bn254.G1Affine, *bn254.G2Affine, error) {
	var alpha, beta1 bn254.G1Affine
	var beta2 bn254.G2Affine
	N := int64(math.Pow(2, float64(power)))
	const HeaderSize = 3
	posAlpha := HeaderSize + 32*(2*N-1)
	posBeta1 := posAlpha + 32*N
	posBeta2 := posBeta1 + 96*N

	dec := bn254.NewDecoder(phase1File)
	// Read AlphaG1
	if _, err := phase1File.Seek(posAlpha, io.SeekStart); err != nil {
		return nil, nil, nil, err
	}
	if err := dec.Decode(&alpha); err != nil {
		return nil, nil, nil, err
	}

	// Read BetaG1
	if _, err := phase1File.Seek(posBeta1, io.SeekStart); err != nil {
		return nil, nil, nil, err
	}
	if err := dec.Decode(&beta1); err != nil {
		return nil, nil, nil, err
	}

	// Read BetaG2
	if _, err := phase1File.Seek(posBeta2, io.SeekStart); err != nil {
		return nil, nil, nil, err
	}
	if err := dec.Decode(&beta2); err != nil {
		return nil, nil, nil, err
	}

	return &alpha, &beta1, &beta2, nil

}

func Is(commitments constraint.Groth16Commitments) bool {
	var isCommitted bool
	for _, commitment := range commitments {
		if len(commitment.PublicAndCommitmentCommitted) > 0 || len(commitment.PrivateCommitted) > 0 {
			isCommitted = true
			break
		}
	}
	return isCommitted
}
