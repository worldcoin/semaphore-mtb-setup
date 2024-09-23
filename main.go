package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:      "setup",
		Usage:     "Use this tool to generate parameters of Groth16 via MPC",
		UsageText: "setup command [arguments...]",
		Commands: []*cli.Command{

			/* ----------------------------- Phase 1 Import ----------------------------- */
			{
				Name:        "p1i",
				Usage:       "p1i <inputPtau> <outputPh1>",
				Description: "Deserialize snarkjs .ptau file into gnark's phase1 format and write to `OUTPUT`.ph1",
				Action:      p1i,
			},
			/* --------------------------- Phase 2 Initialize --------------------------- */
			{
				Name:        "p2n",
				Usage:       "p2n <inputPh1> <inputR1cs> <outputPh2> <outputEvals>",
				Description: "initialize phase 2 for the given circuit",
				Action:      p2n,
			},
			/* --------------------------- Phase 2 Contribute --------------------------- */
			{
				Name:        "p2c",
				Usage:       "p2c <inputPh2> <outputPh2>",
				Description: "contribute phase 2 randomness for Groth16",
				Action:      p2c,
			},
			/* ----------------------------- Phase 2 Verify ----------------------------- */
			{
				Name:        "p2v",
				Usage:       "p2v <inputPath> <originPath>",
				Description: "verify phase 2 contributions for Groth16",
				Action:      p2v,
			},
			/* ----------------------------- Keys Extraction ---------------------------- */
			{
				Name:        "key",
				Usage:       "key <phase1Path> <phase2Path> <phase2EvalsPath> <r1csPath>",
				Description: "extract proving and verifying keys",
				Action:      keys,
			},
			{
				Name:        "sol",
				Usage:       "sol <verifyingKey>",
				Description: "export verifier smart contract from verifying key",
				Action:      sol,
			},

			// Unused since we use the powers of tau ceremony from PPoT
			// /* --------------------------- Phase 1 Initialize --------------------------- */
			// {
			// 	Name:        "p1n",
			// 	Usage:       "p1n <power> <outputPath>",
			// 	Description: "initialize phase 1 of parameters generation for Groth16",
			// 	Action:      p1n,
			// },
			// /* --------------------------- Phase 1 Contribute --------------------------- */
			// {
			// 	Name:        "p1c",
			// 	Usage:       "p1c <inputPath> <outputPath>",
			// 	Description: "contribute phase 1 randomness for Groth16",
			// 	Action:      p1c,
			// },

			// /* ----------------------------- Phase 1 Verify ----------------------------- */
			// {
			// 	Name:        "p1v",
			// 	Usage:       "p1v <inputPath>",
			// 	Description: "verify phase 1 contributions for Groth16",
			// 	Action:      p1v,
			// },
			// /* ------------------ Phase 1 Transform from PPoT Ceremony ------------------ */
			// {
			// 	Name:        "p1t",
			// 	Usage:       "p1t <inputPath> <outputPath> <originalPower> <reducedPower>",
			// 	Description: "transforms output of PPoT ceremony to be usable by semaphore-mtb-setup",
			// 	Action:      p1t,
			// },
			// /* ------------------ Phase 1 Verify from transformed file ------------------ */
			// {
			// 	Name:        "p1vt",
			// 	Usage:       "p1vt <inputPath> <transformedPath",
			// 	Description: "verify phase 1 contributions for Groth16 based on transformed PPoT ceremony file",
			// 	Action:      p1vt,
			// },
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
