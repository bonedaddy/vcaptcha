package main

import (
	"github.com/bonedaddy/vcaptcha/ticket"
	"github.com/gopherjs/gopherjs/js"
)

func main() {
	js.Global.Set("ticket", map[string]interface{}{
		"New": ticket.NewTicket,
	})
}
