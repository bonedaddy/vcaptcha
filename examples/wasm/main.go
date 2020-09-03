package main

import (
	"log"

	"github.com/bonedaddy/vcaptcha/ticket"
)

func main() {
	tick, err := ticket.NewTicket(1)
	if err != nil {
		log.Fatal(err)
	}
	tick.Solve()
}
