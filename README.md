# Guide to the Semaphore Merkle Tree Batcher MPC Contribution Ceremony

This tool allows users to run an MPC ceremony for generating the proving and verifying keys for the Groth16 protocol as presented in [BGM17](https://eprint.iacr.org/2017/1050.pdf). It does not include the beacon contribution since it was proved in [KMSV21](https://eprint.iacr.org/2021/219.pdf) that the security of the generated SRS still holds without it.

## Semaphore Merkle Tree Batcher (SMTB)

[SMTB](http://github.com/worldcoin/semaphore-mtb/) is a service for batch processing of Merkle tree updates. It is designed to be used in conjunction with the [World ID contracts](https://github.com/worldcoin/world-id-contracts) which use [Semaphore](https://github.com/semaphore-protocol/semaphore) as a dependency. It accepts Merkle tree updates and batches them together into a single one. This is useful for reducing the number of transactions that need to be submitted to the blockchain. The correctness of the batched Merkle tree update is assured through the generation of a SNARK (generated through [gnark](https://github.com/ConsenSys/gnark)).

## Reasoning behind a custom trusted setup

Each groth16 proof of a circuit requires a trusted setup that has 2 parts: a phase 1 which is also known as a "Powers of Tau ceremony" which is universal (the same one can be used for any circuit) and a phase2 which is circuit-specific, meaning that you need to a separate phase2 for every single circuit. In order to create an SRS to generate verifying keys for SMTB we would like many different members from different organizations to participate in the phase 2 of the trusted setup.

For the phase 1 we will be reusing the setup done by the joint effort of many community members, it is a powers of tau ceremony with 54 different contributions ([more info here](https://github.com/privacy-scaling-explorations/perpetualpowersoftau)). A list of downloadable `.ptau` files can be found [here](https://github.com/iden3/snarkjs/blob/master/README.md#7-prepare-phase-2).

## Pre-requisites

1. Install git https://github.com/git-guides/install-git
2. Install Go https://go.dev/doc/install
3. Minimum RAM requirement is 16GB

## Phase 2

This phase is circuit-specific, so if you have `n` circuits, then you need to run this phase `n` times.

### snarkjs Powers of Tau deserialization

Download the power 27 `.ptau` file from the [`snarkjs` repository](https://github.com/iden3/snarkjs#7-prepare-phase-2) by running the following command:

```bash
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_27.ptau -O 27.ptau
```

For larger or smaller `.ptau` files, check out the `snarkjs` repository's [README](https://github.com/iden3/snarkjs/tree/master#7-prepare-phase-2) for more information.

Remember that you need sufficiently high powers of tau ceremony to generate a proof for a circuit with a given amount of constraints:

Import phase 1 by deserializing a .ptau file: `semaphore-mtb-setup p1i <ceremony.ptau> <lastPhase1Contribution.ph1>`.

To get a sample r1cs file from `semaphore-mtb`, checkout the [`semaphore-mtb` repository](https://github.com/worldcoin/semaphore-mtb.git) and run the following command:

```bash
git clone https://github.com/worldcoin/semaphore-mtb.git && git checkout wip/mk/r1cs-export
go build
./gnark-mbu r1cs --tree-depth=<TREE_DEPTH> --batch-size=<BATCH_SIZE> --output=demo_smtb.r1cs
```

Move the file into the `semaphore-mtb-setup` directory:

```bash
mv semaphore-mtb/demo_smtb.r1cs semaphore-mtb-setup/smtb.r1cs
```

### Initialization

Depending on the R1CS file, the coordinator runs one of the following commands:

1. Regular R1CS: `semaphore-mtb-setup p2n <lastPhase1Contribution.ph1> <r1cs> <initialPhase2Contribution.ph2>`.
2. Parted R1CS: `semaphore-mtb-setup p2np <phase1Path> <r1csPath> <outputPhase2> <#constraints> <#nbR1C> <batchSize>`

### Contribution

This process is similar to phase 1, except we use commands `p2c` and `p2v`
This is a sequential process that will be repeated for each contributor.

1. The coordinator sends the latest `*.ph2` file to the current contributor
2. The contributor runs the command `semaphore-mtb-setup p2c <input.ph2> <output.ph2>`.
3. Upon successful contribution, the program will output **contribution hash** which must be attested to
4. The contributor sends the output file back to the coordinator
5. The coordinator verifies the file by running `semaphore-mtb-setup p2v <output.ph2> <initialPhase2Contribution.ph2>`.
6. Upon successful verification, the coordinator asks the contributor to attest to their contribution.

**Security Note** It is important for the coordinator to keep track of the contribution hashes output by `semaphore-mtb-setup p2v` to determine whether the user has maliciously replaced previous contributions or re-initiated one on its own

## Keys Extraction

At the end of the ceremony, the coordinator runs `semaphore-mtb-setup keys <lastPhase2Contribution.ph2>` which will output **Groth16 bn254 curve** `pk` and `vk` files

## Phase 1 (Powers of Tau)

This phase is to generate a universal structured reference string (SRS) based on a power `p`.
The value of `2ᵖ` determines the maximum number of constraints for circuits set up in the second phase.

This process will be skipped for the actual ceremony as we will be using the universal SRS generated by the community.

### Participants

1. Coordinator is responsible for initializing, coordinating, and verifying contributions.
2. Contributors are chosen sequentially by the coordinator to contribute randomness to SRS. More importantly, contributors are requested to attest their contributions to the ceremony (e.g. social media announcements).

### Initialization

**Note** Values between `<>` are arguments replaced by actual values during the setup

1. Coordinator run the command `semaphore-mtb-setup p1n <p> <output.ph1>`.

### Contribution

This is a sequential process that will be repeated for each contributor.

1. The coordinator sends the latest `*.ph1` file to the current contributor
2. The contributor runs the command `semaphore-mtb-setup p1c <input.ph1> <output.ph1>`.
3. Upon successful contribution, the program will output **contribution hash** which must be attested to
4. The contributor sends the output file back to the coordinator
5. The coordinator verifies the file by running `semaphore-mtb-setup p1v <output.ph1>`.
6. Upon successful verification, the coordinator asks the contributor to attest to their contribution.

**Security Note** It is important for the coordinator to keep track of the contribution hashes output by `semaphore-mtb-setup p1v` to determine whether the user has maliciously replaced previous contributions or re-initiated one on its own

## Acknowledgements

This repository is a fork of the [zkbnb-setup](https://github.com/bnb-chain/zkbnb-setup/) repository. We would like to thank the authors of the original repository for their work as this project is a slight tweak of the original work to fit our needs.

We appreciate the community efforts to generate [a good universal SRS](https://github.com/privacy-scaling-explorations/perpetualpowersoftau) for everyone's benefit to use and for the [iden3 team for building [snarkjs](https://github.com/iden3/snarkjs).

Also a special thank you to [Kobi Gurkan](https://twitter.com/kobigurk) for his contributions to the [ptau-deserialzier](https://github.com/worldcoin/ptau-deserializer) tool and his advice on the trusted setup process.
