package daemon

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
		args := os.Args[1:]
		if len(args) == 0 {
			return
		}

		for i := 0; i < len(args); i++ {
			if args[i]=="-d" {
				args = append(args[:i], args[i+2:]...)
			}
		}
		command := exec.Command(cmd, args...)
		command.Run()
		fmt.Println("[PID]", command.Process.Pid)
		os.Exit(0)
	}
}
