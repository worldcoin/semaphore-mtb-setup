package main

import (
	"fmt"
	"os"

	ecdsa "github.com/worldcoin/semaphore-mtb-setup/examples/ecdsa"
)

func main() {
	// create a R1CS
	cs, err := ecdsa.BuildR1CS()
	if err != nil {
		fmt.Println(err)
		return
	}

	file, err := os.Create("ecdsa.r1cs")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	_, err = cs.WriteTo(file)
	if err != nil {
		fmt.Println(err)
		return
	}
}
