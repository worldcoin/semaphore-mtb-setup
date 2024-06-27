package main

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"

	deserializer "github.com/worldcoin/ptau-deserializer/deserialize"
	circuit "github.com/worldcoin/semaphore-mtb-setup/examples/ecdsa"
)

/**
Notes:
- len(commitmentInfo) is 814999
- len(pk.G1.K) is different from groth16.Setup vs mpcsetup.InitPhase2 + mpcsetup.ExtractKeys (105941 vs 187441) difference == 81500???
- len(vk.G1.K) is different from groth16.Setup vs mpcsetup.ExtractKeys (2 vs 1) difference == 1

- plan of attack
	- pk.G1.K needs to have the same length
	- InitPhase2
		- pedersen.pk.BasisExpSigma needs to be added to G1 points in ph2.Parameters.G1.L
		- pedersen.vk.GRootSigmaNeg needs to be added to G2 points in ph2.Parameters.G2.Delta
		- phase2 contributions should then apply to the new points
	- ExtractKeys
		- pedersen.pk.BasisExpSigma should be extracted from ph2
		- pedersen.vk.GRootSigmaNeg should be extracted from ph2
		- pedersen.pk.Bases can be derived somehow
		- pedersen.vk.G Can just be fixed
**/

func TestEcdsaMpc(t *testing.T) {
	fmt.Println("Building R1CS...")
	r1cs, witness, err := circuit.BuildR1CS()
	if err != nil {
		t.Fatal(err)
	}
	commitmentInfo := r1cs.CommitmentInfo.(constraint.Groth16Commitments)
	fmt.Println("Number of constraints: ", r1cs.NbConstraints)
	fmt.Println("Len commitment info: ", len(commitmentInfo))
	fmt.Println("Private Commited: ", len(commitmentInfo[0].PrivateCommitted))

	log2 := math.Log2(float64(r1cs.NbConstraints))
	log2Ceil := int(math.Ceil(log2))
	fmt.Println("Log2 of number of constraints: ", log2Ceil)

	ptauFilePath := fmt.Sprintf("examples/ecdsa/ppot_0080_%d.ptau", log2Ceil)
	ptauDownloadLink := fmt.Sprintf("https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_%d.ptau", log2Ceil)
	err = ensureFileExists(ptauFilePath, ptauDownloadLink)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Reading ptau file...")
	ptau, err := deserializer.ReadPtau(ptauFilePath)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Converting ptau to phase1...")
	phase1, err := deserializer.ConvertPtauToPhase1(ptau)
	if err != nil {
		t.Fatal(err)
	}

	// This process is deterministic
	fmt.Println("Initializing phase2...")
	phase2, evals := mpcsetup.InitPhase2(r1cs, &phase1)

	// // TODO: This is completely broken.
	// fmt.Println("Initializing Commitment Bases...")
	// commitmentBases, err := InitCommitmentBases(r1cs, &evals)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	//
	// fmt.Println("Initializing Pedersen Keys...")
	// pedersenKeys, err := InitPedersen(commitmentBases...)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	//
	// fmt.Println("Running phase2 contribution...")
	// phase2Final := phase2
	// phase2Final.Contribute()
	//
	// fmt.Println("Running pedersen contribution...")
	// pedersenKeysFinal := pedersenKeys
	// pedersenKeysFinal.Contribute()
	//
	// fmt.Println("Running phase2 verification...")
	// mpcsetup.VerifyPhase2(&phase2, &phase2Final)

	// fmt.Println("Inserting G1 point into evals...")
	// evals.G1.VKK = append(evals.G1.VKK, pedersenKeysFinal.VK.GRootSigmaNeg...)

	// fmt.Println("Inserting G1 points into phase2...")
	// phase2Final.Parameters.G1.L = append(phase2Final.Parameters.G1.L, pedersenKeysFinal.PK[0].BasisExpSigma...)
	//
	// fmt.Println("Extracting keys...")
	// pk, vk := mpcsetup.ExtractKeys(&phase1, &phase2Final, &evals, r1cs.NbConstraints)
	// pk.CommitmentKeys = pedersenKeys.PK
	// vk.CommitmentKey = pedersenKeys.VK

	fmt.Println("Extracting keys...")
	pk, vk := mpcsetup.ExtractKeys(r1cs, &phase1, &phase2, &evals)

	fmt.Println("Running local setup...")
	lpk, lvk, err := groth16.Setup(r1cs)
	if err != nil {
		t.Fatal(err)
	}
	// pk.G1.K = lpk1.(*groth16_bn254.ProvingKey).G1.K
	// vk.G1.K = lvk1.(*groth16_bn254.VerifyingKey).G1.K

	// pedersenKeys := PedersenKeys{}
	// pedersenKeys.PK = lpk1.(*groth16_bn254.ProvingKey).CommitmentKeys
	// pedersenKeys.VK = lvk1.(*groth16_bn254.VerifyingKey).CommitmentKey
	//
	// pedersenKeys.Contribute()
	// lpk1.(*groth16_bn254.ProvingKey).CommitmentKeys = pedersenKeys.PK
	// lvk1.(*groth16_bn254.VerifyingKey).CommitmentKey = pedersenKeys.VK

	// Diagnoticss

	fmt.Printf("pk.G1.Alpha: %d, pk.G1.Beta: %d, pk.G1.Delta: %d\n", pk.G1.Alpha, pk.G1.Beta, pk.G1.Delta)
	fmt.Printf("lpk.G1.Alpha: %d, lpk.G1.Beta: %d, lpk.G1.Delta: %d\n\n", lpk.(*groth16_bn254.ProvingKey).G1.Alpha, lpk.(*groth16_bn254.ProvingKey).G1.Beta, lpk.(*groth16_bn254.ProvingKey).G1.Delta)

	fmt.Printf("pk.G1.A: %d, pk.G1.B: %d, pk.G1.Z: %d\n", len(pk.G1.A), len(pk.G1.B), len(pk.G1.Z))
	fmt.Printf("lpk.G1.A: %d, lpk.G1.B: %d, lpk.G1.Z: %d\n\n", len(lpk.(*groth16_bn254.ProvingKey).G1.A), len(lpk.(*groth16_bn254.ProvingKey).G1.B), len(lpk.(*groth16_bn254.ProvingKey).G1.Z))

	fmt.Printf("pk.G1.K: %d, pk.G2.B: %d\n", len(pk.G1.K), len(pk.G2.B))
	fmt.Printf("lpk.G1.K: %d, lpk.G2.B: %d\n\n", len(lpk.(*groth16_bn254.ProvingKey).G1.K), len(lpk.(*groth16_bn254.ProvingKey).G2.B))

	fmt.Printf("pk.InfinityA: %d, pk.InfinityB: %d\n\n", len(pk.InfinityA), len(pk.InfinityB))

	fmt.Printf("vk.G1.K: %d\n", len(vk.G1.K))
	fmt.Printf("lvk.G1.K: %d\n\n", len(lvk.(*groth16_bn254.VerifyingKey).G1.K))

	fmt.Printf("vk.PublicAndCommitmentCommitted: %d\n", len(vk.PublicAndCommitmentCommitted))
	fmt.Printf("lvk.PublicAndCommitmentCommitted: %d\n\n", len(lvk.(*groth16_bn254.VerifyingKey).PublicAndCommitmentCommitted))

	fmt.Printf("len(pk.CommitmentKeys[0].BasisExpSigma): %d\n", len(pk.CommitmentKeys[0].BasisExpSigma))
	fmt.Printf("len(lpk.CommitmentKeys[0].BasisExpSigma): %d\n\n", len(lpk.(*groth16_bn254.ProvingKey).CommitmentKeys[0].BasisExpSigma))

	fmt.Println("Proving...")
	proof, err := groth16.Prove(r1cs, &pk, *witness)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Verifying poof...")
	pubWitness, err := (*witness).Public()
	if err != nil {
		t.Fatal(err)
	}
	err = groth16.Verify(proof, &vk, pubWitness)
	if err != nil {
		t.Fatal(err)
	}

	// fmt.Println("Exporting Solidity...")
	// solFile, err := os.Create("examples/ecdsa/ecdsa.sol")
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// err = vk.ExportSolidity(solFile)
	// if err != nil {
	// 	t.Fatal(err)
	// }
}

func ensureFileExists(filePath, url string) error {
	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// File does not exist, download it
		fmt.Printf("File does not exist, downloading from %s...\n", url)
		if err = downloadFile(filePath, url); err != nil {
			return fmt.Errorf("failed to download file: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check if file exists: %v", err)
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// You can use the file here (e.g., read from it, etc.)
	fmt.Println("File opened successfully")
	return nil
}

func downloadFile(filePath, url string) error {
	// Create the directories if they do not exist
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create directories: %v", err)
	}

	// Create the file
	out, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download file: %v", err)
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	return nil
}
