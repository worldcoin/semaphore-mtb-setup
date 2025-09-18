package keys

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/worldcoin/semaphore-mtb-setup/phase2"
)

type VerifyingKey struct {
	G1 struct {
		Alpha       bn254.G1Affine
		Beta, Delta bn254.G1Affine   // unused, here for compatibility purposes
		K           []bn254.G1Affine // The indexes correspond to the public wires
	}

	G2 struct {
		Beta, Delta, Gamma bn254.G2Affine
	}

	CommitmentKey  pedersen.VerifyingKey
	CommitmentInfo constraint.Commitment // since the verifier doesn't input a constraint system, this needs to be provided here
}

func (vk *VerifyingKey) writeTo(w io.Writer) (int64, error) {
	enc := bn254.NewEncoder(w, bn254.RawEncoding())

	// [α]1,[β]1,[β]2,[γ]2,[δ]1,[δ]2
	if err := enc.Encode(&vk.G1.Alpha); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G1.Beta); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Beta); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Gamma); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G1.Delta); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Delta); err != nil {
		return enc.BytesWritten(), err
	}

	// uint32(len(Kvk)),[Kvk]1
	if err := enc.Encode(vk.G1.K); err != nil {
		return enc.BytesWritten(), err
	}

	return enc.BytesWritten(), nil
}

func extractPK(phase2Path string, commitmentKeys []pedersen.ProvingKey) error {
	// Phase 2 file
	phase2File, err := os.Open(phase2Path)
	if err != nil {
		return err
	}
	defer phase2File.Close()

	// Evaluations
	evalsFile, err := os.Open("evals")
	if err != nil {
		return err
	}
	defer evalsFile.Close()

	// Use buffered IO to write parameters efficiently
	ph2Reader := bufio.NewReader(phase2File)
	evalsReader := bufio.NewReader(evalsFile)

	var header phase2.Header
	if err := header.Read(ph2Reader); err != nil {
		return err
	}

	decPh2 := bn254.NewDecoder(ph2Reader)
	decEvals := bn254.NewDecoder(evalsReader)

	pkFile, err := os.Create("pk")
	if err != nil {
		return err
	}
	defer pkFile.Close()
	pkWriter := bufio.NewWriter(pkFile)
	defer pkWriter.Flush()
	encPk := bn254.NewEncoder((pkWriter))

	var alphaG1, betaG1, deltaG1 bn254.G1Affine
	var betaG2, deltaG2 bn254.G2Affine

	// 0. Write domain
	domain := fft.NewDomain(uint64(header.Domain))
	domain.WriteTo(pkWriter)

	// 1. Read/Write [α]₁
	if err := decEvals.Decode(&alphaG1); err != nil {
		return err
	}
	if err := encPk.Encode(&alphaG1); err != nil {
		return err
	}

	// 2. Read/Write [β]₁
	if err := decEvals.Decode(&betaG1); err != nil {
		return err
	}
	if err := encPk.Encode(&betaG1); err != nil {
		return err
	}

	// 3. Read/Write [δ]₁
	if err := decPh2.Decode(&deltaG1); err != nil {
		return err
	}
	if err := encPk.Encode(&deltaG1); err != nil {
		return err
	}

	// Read [β]₂
	if err := decEvals.Decode(&betaG2); err != nil {
		return err
	}
	// Read [δ]₂
	if err := decPh2.Decode(&deltaG2); err != nil {
		return err
	}

	// 4. Read, Filter, Write A
	var buffG1 []bn254.G1Affine
	if err := decEvals.Decode(&buffG1); err != nil {
		return err
	}
	buffG1, infinityA, nbInfinityA := filterInfinityG1(buffG1)
	if err := encPk.Encode(buffG1); err != nil {
		return err
	}

	// 5. Read, Filter, Write B
	if err := decEvals.Decode(&buffG1); err != nil {
		return err
	}
	buffG1, infinityB, nbInfinityB := filterInfinityG1(buffG1)
	if err := encPk.Encode(buffG1); err != nil {
		return err
	}

	// 6. Read/Write Z
	buffG1 = make([]bn254.G1Affine, header.Domain)
	for i := 0; i < header.Domain; i++ {
		if err := decPh2.Decode(&buffG1[i]); err != nil {
			return err
		}
	}
	if err := encPk.Encode(buffG1); err != nil {
		return err
	}

	// 7. Read/Write PKK
	buffG1 = make([]bn254.G1Affine, header.Witness)
	for i := 0; i < header.Witness; i++ {
		if err := decPh2.Decode(&buffG1[i]); err != nil {
			return err
		}
	}
	if err := encPk.Encode(buffG1); err != nil {
		return err
	}

	// 8. Write [β]₂
	if err := encPk.Encode(&betaG2); err != nil {
		return err
	}

	// 9. Write [δ]₂
	if err := encPk.Encode(&deltaG2); err != nil {
		return err
	}

	// 10. Read, Filter, Write B₂
	var buffG2 []bn254.G2Affine
	if err := decEvals.Decode(&buffG2); err != nil {
		return err
	}
	buffG2, _, _ = filterInfinityG2(buffG2)
	if err := encPk.Encode(buffG2); err != nil {
		return err
	}
	buffG2 = nil

	// 11. Write nbWires
	nbWires := uint64(header.Wires)
	if err := encPk.Encode(&nbWires); err != nil {
		return err
	}

	// 12. Write nbInfinityA
	if err := encPk.Encode(&nbInfinityA); err != nil {
		return err
	}

	// 13. Write nbInfinityB
	if err := encPk.Encode(&nbInfinityB); err != nil {
		return err
	}

	// 14. Write infinityA
	if err := encPk.Encode(&infinityA); err != nil {
		return err
	}

	// 15. Write infinityB
	if err := encPk.Encode(&infinityB); err != nil {
		return err
	}

	// 16. Write length of commitment keys
	if err := encPk.Encode(uint32(len(commitmentKeys))); err != nil {
		return err
	}

	// 17. Write commitment keys
	for _, ck := range commitmentKeys {
		_, err := ck.WriteTo(pkWriter)
		if err != nil {
			return err
		}
	}

	return nil
}

func extractVK(phase2Path string) ([]pedersen.ProvingKey, error) {
	vk := VerifyingKey{}
	// Phase 2 file
	phase2File, err := os.Open(phase2Path)
	if err != nil {
		return nil, err
	}
	defer phase2File.Close()

	// Evaluations
	evalsFile, err := os.Open("evals")
	if err != nil {
		return nil, err
	}
	defer evalsFile.Close()

	// Use buffered IO to write parameters efficiently
	ph2Reader := bufio.NewReader(phase2File)
	evalsReader := bufio.NewReader(evalsFile)

	var header phase2.Header
	if err := header.Read(ph2Reader); err != nil {
		return nil, err
	}

	decPh2 := bn254.NewDecoder(ph2Reader)
	decEvals := bn254.NewDecoder(evalsReader)

	vkFile, err := os.Create("vk")
	if err != nil {
		return nil, err
	}
	defer vkFile.Close()
	vkWriter := bufio.NewWriter(vkFile)
	defer vkWriter.Flush()

	// 1. Read [α]₁
	if err := decEvals.Decode(&vk.G1.Alpha); err != nil {
		return nil, err
	}

	// 2. Read [β]₁
	if err := decEvals.Decode(&vk.G1.Beta); err != nil {
		return nil, err
	}

	// 3. Read [β]₂
	if err := decEvals.Decode(&vk.G2.Beta); err != nil {
		return nil, err
	}

	// 4. Set [γ]₂
	_, _, _, gammaG2 := bn254.Generators()
	vk.G2.Gamma.Set(&gammaG2)

	// 5. Read [δ]₁
	if err := decPh2.Decode(&vk.G1.Delta); err != nil {
		return nil, err
	}

	// 6. Read [δ]₂
	if err := decPh2.Decode(&vk.G2.Delta); err != nil {
		return nil, err
	}

	// 7. Read VKK
	pos := int64(128*(header.Wires+1) + 12)
	if _, err := evalsFile.Seek(pos, io.SeekStart); err != nil {
		return nil, err
	}
	evalsReader.Reset(evalsFile)
	if err := decEvals.Decode(&vk.G1.K); err != nil {
		return nil, err
	}

	// 8. Setup commitment key
	var ckk []bn254.G1Affine
	if err := decEvals.Decode(&ckk); err != nil {
		return nil, err
	}
	var pk []pedersen.ProvingKey
	pk, vk.CommitmentKey, err = pedersen.Setup(ckk)
	if err != nil {
		return nil, err
	}
	if _, err := vk.writeTo(vkWriter); err != nil {
		return nil, err
	}
	return pk, nil
}

func ExtractKeys(phase2Path string) error {
	fmt.Println("Extracting verifying key")
	pk, err := extractVK(phase2Path)
	if err != nil {
		return err
	}
	fmt.Println("Extracting proving key")
	if err := extractPK(phase2Path, pk); err != nil {
		return err
	}
	fmt.Println("Keys have been extracted successfully")
	return nil
}

func ExportSol(session string) error {
	filename := session + ".sol"
	fmt.Printf("Exporting %s\n", filename)
	f, _ := os.Open(session + ".vk.save")
	verifyingKey := groth16.NewVerifyingKey(ecc.BN254)
	_, err := verifyingKey.ReadFrom(f)
	if err != nil {
		panic(fmt.Errorf("read file error"))
	}
	err = f.Close()
	f, err = os.Create(filename)
	if err != nil {
		panic(err)
	}
	err = verifyingKey.ExportSolidity(f)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s has been extracted successfully\n", filename)
	return nil
}

func filterInfinityG1(buff []bn254.G1Affine) ([]bn254.G1Affine, []bool, uint64) {
	infinityAt := make([]bool, len(buff))
	filtered := make([]bn254.G1Affine, len(buff))
	j := 0
	for i, e := range buff {
		if e.IsInfinity() {
			infinityAt[i] = true
			continue
		}
		filtered[j] = buff[i]
		j++
	}
	return filtered[:j], infinityAt, uint64(len(buff) - j)
}

func filterInfinityG2(buff []bn254.G2Affine) ([]bn254.G2Affine, []bool, uint64) {
	infinityAt := make([]bool, len(buff))
	filtered := make([]bn254.G2Affine, len(buff))
	j := 0
	for i, e := range buff {
		if e.IsInfinity() {
			infinityAt[i] = true
			continue
		}
		filtered[j] = buff[i]
		j++
	}
	return filtered[:j], infinityAt, uint64(len(buff) - j)

}
