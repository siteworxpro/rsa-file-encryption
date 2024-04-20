package printer

import (
	"fmt"
)

var Version = "0.0.0"

type Printer struct {
}

func NewPrinter() *Printer {
	return &Printer{}
}

func (p *Printer) PrintTitle() {
	fmt.Println(p.getBright().Render(fmt.Sprintf("RSA File Encryption Tool %s", Version)))
	fmt.Println()
}
