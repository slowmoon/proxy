package internal

import (
	"flag"
	"os"
	"os/exec"
	"fmt"
)

var daemon bool

func init() {
	flag.BoolVar(&daemon, "d", false, "use the daemon command -d=true")

	if !flag.Parsed() {
		flag.Parse()
	}

	if daemon {
		cmd := os.Args[0]
		args := os.Args[2:]

		command := exec.Command(cmd, args...)
		command.Start()
		fmt.Println("[PID]", command.Process.Pid)
		os.Exit(0)
	}
}
