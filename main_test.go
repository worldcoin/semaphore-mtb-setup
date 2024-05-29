package main

import (

	// "crypto/rand"
	// "math/big"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	// "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	// "github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	ecdsa "github.com/worldcoin/semaphore-mtb-setup/examples/ecdsa"

	deserializer "github.com/worldcoin/ptau-deserializer/deserialize"
)

func TestEcdsaComplete(t *testing.T) {
	err := testSetup()
	if err != nil {
		t.Error(err)
	}
}

func testSetup() error {
	ptauFilePath := "examples/ecdsa/ppot_0080_13.ptau"
	ptauDownloadLink := "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_13.ptau"
	err := ensureFileExists(ptauFilePath, ptauDownloadLink)
	if err != nil {
		return err
	}

	fmt.Println("Building R1CS...")
	r1cs, err := ecdsa.BuildR1CS()
	if err != nil {
		return err
	}

	fmt.Println("Reading ptau file...")
	ptau, err := deserializer.ReadPtau(ptauFilePath)
	if err != nil {
		return err
	}

	fmt.Println("Converting ptau to phase1...")
	phase1, err := deserializer.ConvertPtauToPhase1(ptau)
	if err != nil {
		return err
	}

	fmt.Println("Initializing phase2...")
	phase2, evals := mpcsetup.InitPhase2(r1cs, &phase1)

	fmt.Println("Initializing pedersen keys...")
	pedersenKeys := PedersenKeys{}
	pedersenKeys.PK, pedersenKeys.VK, err = pedersen.Setup(evals.G1.VKK)
	if err != nil {
		return err
	}

	fmt.Println("Running phase2 contribution...")
	phase2Final := phase2
	phase2Final.Contribute()

	fmt.Println("Running pedersen contribution...")
	pedersenKeysFinal := pedersenKeys
	pedersenKeysFinal.Contribute()

	fmt.Println("Running phase2 verification...")
	mpcsetup.VerifyPhase2(&phase2, &phase2Final)

	fmt.Println("Extracting keys...")
	pk, vk := mpcsetup.ExtractKeys(&phase1, &phase2Final, &evals, r1cs.NbConstraints)
	pk.CommitmentKeys = pedersenKeysFinal.PK
	vk.CommitmentKey = pedersenKeysFinal.VK

	fmt.Println("Exporting Solidity...")
	solFile, err := os.Create("examples/ecdsa/ecdsa.sol")
	if err != nil {
		return err
	}
	err = vk.ExportSolidity(solFile)

	return err
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
