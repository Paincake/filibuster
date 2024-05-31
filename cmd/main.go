package main

import (
	"github.com/Paincake/filibuster/cli"
	"os"
)

func main() {
	if os.Args[1] == cli.Check {
		cmd, err := cli.NewCheckLfiCommand()
		if err != nil {
			panic(err)
		}
		cmd.CheckLFI()
	}
}
