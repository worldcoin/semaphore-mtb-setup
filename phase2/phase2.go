package phase2

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/worldcoin/semaphore-mtb-setup/common"
)

func Initialize(phase1Path, r1csPath, phase2Path string) error {
	phase1File, err := os.Open(phase1Path)
	if err != nil {
		return err
	}
	defer phase1File.Close()

	phase2File, err := os.Create(phase2Path)
	if err != nil {
		return err
	}
	defer phase2File.Close()

	// 1. Process Headers
	header1, header2, err := processHeader(r1csPath, phase1File, phase2File)
	if err != nil {
		return err
	}

	// 2. Convert phase 1 SRS to Lagrange basis
	if err := processLagrange(header1, header2, phase1File, phase2File); err != nil {
		return err
	}

	// 3. Process evaluation
	if err := processEvaluations(header1, header2, r1csPath, phase1File); err != nil {
		return err
	}

	// Evaluate Delta and Z
	if err := processDeltaAndZ(header1, header2, phase1File, phase2File); err != nil {
		return err
	}

	// Process parameters
	if err := processPVCKK(header1, header2, r1csPath, phase2File); err != nil {
		return err
	}

	fmt.Println("Phase 2 has been initialized successfully")
	return nil
}

func Contribute(inputPath, outputPath string) error {
	// Input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inputFile.Close()
	reader := bufio.NewReader(inputFile)
	dec := bn254.NewDecoder(reader)

	// Output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()
	writer := bufio.NewWriter(outputFile)
	defer writer.Flush()
	enc := bn254.NewEncoder(writer)

	// Read/Write header with extra contribution
	var header Header
	if err := header.Read(reader); err != nil {
		return err
	}
	fmt.Printf("Current #Contributions := %d\n", header.Contributions)
	header.Contributions++
	if err := header.write(writer); err != nil {
		return err
	}

	// Sample toxic parameters
	fmt.Println("Sampling toxic parameters Delta")
	// Sample toxic δ
	var delta, deltaInv fr.Element
	var deltaBI, deltaInvBI big.Int
	delta.SetRandom()
	deltaInv.Inverse(&delta)

	delta.BigInt(&deltaBI)
	deltaInv.BigInt(&deltaInvBI)

	// Process δ₁
	fmt.Println("Processing DeltaG1 and DeltaG2")
	var delta1 bn254.G1Affine
	if err := dec.Decode(&delta1); err != nil {
		return err
	}
	delta1.ScalarMultiplication(&delta1, &deltaBI)
	if err := enc.Encode(&delta1); err != nil {
		return err
	}

	// Process δ₂
	var delta2 bn254.G2Affine
	if err := dec.Decode(&delta2); err != nil {
		return err
	}
	delta2.ScalarMultiplication(&delta2, &deltaBI)
	if err := enc.Encode(&delta2); err != nil {
		return err
	}

	// Process Z using δ⁻¹
	if err = scale(dec, enc, header.Domain, &deltaInvBI); err != nil {
		return err
	}

	// Process PKK using δ⁻¹
	if err = scale(dec, enc, header.Witness, &deltaInvBI); err != nil {
		return err
	}

	// Copy old contributions
	nExistingContributions := header.Contributions - 1
	var c Contribution
	for i := 0; i < nExistingContributions; i++ {
		if _, err := c.readFrom(reader); err != nil {
			return err
		}
		if _, err := c.writeTo(writer); err != nil {
			return err
		}
	}

	// Get hash of previous contribution
	var prevHash []byte
	if nExistingContributions == 0 {
		prevHash = nil
	} else {
		prevHash = c.Hash
	}

	var contribution Contribution
	contribution.Delta.Set(&delta1)
	contribution.PublicKey = common.GenPublicKey(delta, prevHash, 1)
	contribution.Hash = computeHash(&contribution)

	// Write the contribution
	contribution.writeTo(writer)

	fmt.Println("Contribution has been successful!")
	fmt.Println("Contribution Hash := ", hex.EncodeToString(contribution.Hash))

	return nil
}

func Verify(inputPath, originPath string) error {
	// Input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	// Origin file from Phase2.Initialize
	originFile, err := os.Open(originPath)
	if err != nil {
		return err
	}
	defer originFile.Close()

	inputReader := bufio.NewReader(inputFile)
	inputDec := bn254.NewDecoder(inputReader)
	originReader := bufio.NewReader(originFile)
	originDec := bn254.NewDecoder(originReader)

	// Read curHeader
	var curHeader, orgHeader Header
	if err := curHeader.Read(inputReader); err != nil {
		return err
	}

	if err := orgHeader.Read(originReader); err != nil {
		return err
	}
	if curHeader.Contributions == 0 {
		return fmt.Errorf("there are no contributions to verify")
	}
	if !curHeader.Equal(&orgHeader) {
		return fmt.Errorf("there is a mismatch between origin and curren headers for phase 2")
	}

	// Read [δ]₁ and [δ]₂
	var d1, g1 bn254.G1Affine
	var d2, g2 bn254.G2Affine
	if err := originDec.Decode(&g1); err != nil {
		return err
	}
	if err := originDec.Decode(&g2); err != nil {
		return err
	}
	if err := inputDec.Decode(&d1); err != nil {
		return err
	}
	if err := inputDec.Decode(&d2); err != nil {
		return err
	}

	// Check δ₁ and δ₂ are consistent
	if !common.SameRatio(g1, d1, d2, g2) {
		return fmt.Errorf("deltaG1 and deltaG2 aren't consistent")
	}

	// Check Z is updated correctly from origin to the latest state
	fmt.Println("Verifying update of Z")
	if err := verifyParameter(&d2, &g2, inputDec, originDec, curHeader.Domain, "Z"); err != nil {
		return err
	}

	// Check PKK is updated correctly from origin to the latest state
	fmt.Println("Verifying update of PKK")
	if err := verifyParameter(&d2, &g2, inputDec, originDec, curHeader.Witness, "PKK"); err != nil {
		return err
	}

	// Verify contributions
	fmt.Printf("#Contributions := %d\n", curHeader.Contributions)
	var prevDelta = g1
	var prevHash []byte = nil
	var c Contribution
	for i := 0; i < curHeader.Contributions; i++ {
		if _, err := c.readFrom(inputReader); err != nil {
			return err
		}
		fmt.Printf("Verifying contribution %d with Hash := %s\n", i+1, hex.EncodeToString(c.Hash))
		if err := verifyContribution(&c, prevDelta, prevHash); err != nil {
			return err
		}
		prevDelta = c.Delta
		prevHash = c.Hash
	}

	// Verify last contribution has the same delta in parameters
	fmt.Println("Verifying Delta of last contribution")
	if !c.Delta.Equal(&d1) {
		return fmt.Errorf("delta of last contribution delta isn't the same as in parameters")
	}

	fmt.Println("Contributions verification has been successful")
	return nil
}
