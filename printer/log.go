package printer

import (
	"fmt"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"time"
)

func (p *Printer) LogSuccess(message string) {
	fmt.Println(p.getSuccess().Render("✅  " + message))
}

func (p *Printer) LogInfo(message string) {
	fmt.Println(p.getInfo().Render("ℹ️   " + message))
}

func (p *Printer) LogError(message string) {
	fmt.Println(p.getError().Render("❌  " + message))
}

type model struct {
	spinner  spinner.Model
	quitting bool
	err      error
	message  string
}

func (*Printer) LogSpinner(message string, done chan bool) {
	p := tea.NewProgram(initialModel(message))

	go p.Run()

	for {
		select {
		case <-done:
			p.Kill()
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func initialModel(message string) model {
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).PaddingTop(1).PaddingLeft(2)

	return model{spinner: s, message: message}
}

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}

type errMsg error

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		default:
			return m, nil
		}

	case errMsg:
		m.err = msg
		return m, nil

	default:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
}

func (m model) View() string {
	if m.err != nil {
		return m.err.Error()
	}
	str := fmt.Sprintf("  %s %s\n\n", m.spinner.View(), m.message)
	if m.quitting {
		return str + "\n"
	}
	return str
}
