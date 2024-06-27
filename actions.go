package main

import (
	"errors"
	"fmt"
	"os"

	groth16 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/urfave/cli/v2"
	deserializer "github.com/worldcoin/ptau-deserializer/deserialize"
)

func p1i(cCtx *cli.Context) error {
	ptauFilePath := cCtx.Args().Get(0)
	outputFilePath := cCtx.Args().Get(1)

	ptau, err := deserializer.ReadPtau(ptauFilePath)
	if err != nil {
		return err
	}

	phase1, err := deserializer.ConvertPtauToPhase1(ptau)
	if err != nil {
		return err
	}
	fmt.Println("Phase1 generated")

	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}

	_, err = phase1.WriteTo(outputFile)
	if err != nil {
		return err
	}
	fmt.Println("Phase1 written to", outputFilePath)

	return nil
}

func p2n(cCtx *cli.Context) error {
	// if cCtx.Args().Len() != 4 {
	// 	return errors.New("please provide the correct arguments")
	// }
	//
	// phase1Path := cCtx.Args().Get(0)
	// r1csPath := cCtx.Args().Get(1)
	// phase2Path := cCtx.Args().Get(2)
	// evalsPath := cCtx.Args().Get(3)
	//
	// phase1File, err := os.Open(phase1Path)
	// if err != nil {
	// 	return err
	// }
	// phase1 := &mpcsetup.Phase1{}
	// phase1.ReadFrom(phase1File)
	//
	// r1csFile, err := os.Open(r1csPath)
	// if err != nil {
	// 	return err
	// }
	// r1cs := cs.R1CS{}
	// r1cs.ReadFrom(r1csFile)
	//
	// pedersenKeys := PedersenKeys{}
	//
	// phase2, evals := mpcsetup.InitPhase2(&r1cs, phase1)
	// pedersenKeys.PK, pedersenKeys.VK, err = pedersen.Setup(evals.G1.VKK)
	// if err != nil {
	// 	return err
	// }
	//
	// phase2File, err := os.Create(phase2Path)
	// if err != nil {
	// 	return err
	// }
	// phase2.WriteTo(phase2File)
	//
	// evalsFile, err := os.Create(evalsPath)
	// if err != nil {
	// 	return err
	// }
	// evals.WriteTo(evalsFile)
	//
	// pedersenKeysFile, err := os.Create("pedersenKeys")
	// if err != nil {
	// 	return err
	// }
	// pedersenKeys.WriteTo(pedersenKeysFile)

	return nil
}

func p2c(cCtx *cli.Context) error {
	// if cCtx.Args().Len() != 4 {
	// 	return errors.New("please provide the correct arguments")
	// }
	// inputPh2Path := cCtx.Args().Get(0)
	// outputPh2Path := cCtx.Args().Get(1)
	// inputPedersenPath := cCtx.Args().Get(2)
	// outputPedersenPath := cCtx.Args().Get(3)
	//
	// inputFile, err := os.Open(inputPh2Path)
	// if err != nil {
	// 	return err
	// }
	// phase2 := &mpcsetup.Phase2{}
	// phase2.ReadFrom(inputFile)
	//
	// inputPedersenFile, err := os.Open(inputPedersenPath)
	// if err != nil {
	// 	return err
	// }
	// pedersen := PedersenKeys{}
	// pedersen.ReadFrom(inputPedersenFile)
	//
	// phase2.Contribute()
	// pedersen.Contribute()
	//
	// outputFile, err := os.Create(outputPh2Path)
	// if err != nil {
	// 	return err
	// }
	// phase2.WriteTo(outputFile)
	//
	// outputPedersenFile, err := os.Create(outputPedersenPath)
	// if err != nil {
	// 	return err
	// }
	// pedersen.WriteTo(outputPedersenFile)

	return nil
}

func p2v(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 2 {
		return errors.New("please provide the correct arguments")
	}
	inputPath := cCtx.Args().Get(0)
	originPath := cCtx.Args().Get(1)

	inputFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	input := &mpcsetup.Phase2{}
	input.ReadFrom(inputFile)

	originFile, err := os.Open(originPath)
	if err != nil {
		return err
	}
	origin := &mpcsetup.Phase2{}
	origin.ReadFrom(originFile)

	mpcsetup.VerifyPhase2(origin, input)

	return nil
}

func extractKeys(cCtx *cli.Context) error {
	// // sanity check
	// if cCtx.Args().Len() != 4 {
	// 	return errors.New("please provide the correct arguments")
	// }
	//
	// phase1Path := cCtx.Args().Get(0)
	// phase1 := &mpcsetup.Phase1{}
	// phase1File, err := os.Open(phase1Path)
	// if err != nil {
	// 	return err
	// }
	// phase1.ReadFrom(phase1File)
	//
	// phase2Path := cCtx.Args().Get(1)
	// phase2 := &mpcsetup.Phase2{}
	// phase2File, err := os.Open(phase2Path)
	// if err != nil {
	// 	return err
	// }
	// phase2.ReadFrom(phase2File)
	//
	// evalsPath := cCtx.Args().Get(2)
	// evals := &mpcsetup.Phase2Evaluations{}
	// evalsFile, err := os.Open(evalsPath)
	// if err != nil {
	// 	return err
	// }
	// evals.ReadFrom(evalsFile)
	//
	// e, _ := json.Marshal(evals)
	// fmt.Println(string(e))
	//
	// r1csPath := cCtx.Args().Get(3)
	// r1cs := &cs.R1CS{}
	// r1csFile, err := os.Open(r1csPath)
	// if err != nil {
	// 	return err
	// }
	// r1cs.ReadFrom(r1csFile)
	//
	// pk, vk := mpcsetup.ExtractKeys(phase1, phase2, evals, r1cs.NbConstraints)
	//
	// pkFile, err := os.Create("pk")
	// if err != nil {
	// 	return err
	// }
	// pk.WriteTo(pkFile)
	//
	// vkFile, err := os.Create("vk")
	// if err != nil {
	// 	return err
	// }
	// vk.WriteTo(vkFile)

	return nil
}

func exportSol(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 1 {
		return errors.New("please provide the correct arguments")
	}

	vkPath := cCtx.Args().Get(0)
	vk := &groth16.VerifyingKey{}
	vkFile, err := os.Open(vkPath)
	if err != nil {
		return err
	}
	vk.ReadFrom(vkFile)

	solFile, err := os.Create("verifier.sol")
	if err != nil {
		return err
	}

	err = vk.ExportSolidity(solFile)
	return err
}
