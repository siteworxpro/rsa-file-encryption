package printer

import (
	"github.com/charmbracelet/lipgloss"
)

func (*Printer) getBright() lipgloss.Style {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#EDEEEDFF")).
		Background(lipgloss.Color("#424E46FF")).
		MarginTop(1).
		PaddingLeft(3).
		PaddingRight(3)
}

func (*Printer) getSuccess() lipgloss.Style {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FF00")).
		MarginTop(1).
		MarginBottom(2).
		PaddingLeft(2).
		Width(120)
}

func (*Printer) getError() lipgloss.Style {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FF0000")).
		PaddingLeft(2).
		MarginTop(1).
		MarginBottom(2).
		Width(120)
}

func (*Printer) getInfo() lipgloss.Style {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#4E82B7FF")).
		PaddingLeft(2).
		Width(120)
}
