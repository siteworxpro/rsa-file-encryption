package printer

import (
	"fmt"
	"time"
)

func (p *Printer) LogSuccess(message string) {
	fmt.Println(p.getSuccess().Render("✅  " + message))
}

func (p *Printer) LogInfo(message string) {
	fmt.Println(p.getInfo().Render("ℹ️  " + message))
}

func (p *Printer) LogError(message string) {
	fmt.Println(p.getError().Render("❌  " + message))
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func (*Printer) LogSpinner(message string, done chan bool) {
	fmt.Print("\033[?25l") // hide cursor
	ticker := time.NewTicker(80 * time.Millisecond)
	defer func() {
		ticker.Stop()
		fmt.Print("\r\033[K\033[?25h\n") // clear line, show cursor, newline
	}()

	i := 0
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			fmt.Printf("\r  %s %s", spinnerFrames[i%len(spinnerFrames)], message)
			i++
		}
	}
}
