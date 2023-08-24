package main

import (
	"os"

	"github.com/bonedaddy/vcaptcha/ticket"
	"github.com/gopherjs/gopherjs/js"
)

func main() {
	js.Global.Set("ticket", map[string]interface{}{
		"New": New,
	})
}

func New(diff int) *js.Object {
	tick, err := ticket.NewTicket(diff)
	if err != nil {
		os.Exit(1)
	}
	return js.MakeWrapper(tick)
}
