package internal

import (
	"log"
	"os"
)


type Debug bool

var logger = log.New(os.Stdout, "[DEBUG]", log.Ltime)


func (d Debug)Println(args...interface{}){

	if d {
		logger.Println(args)
	}
}

func (d Debug)Printf(fmt string, args...interface{}) {
	if d {
	   logger.Printf(fmt, args)
	}
}
