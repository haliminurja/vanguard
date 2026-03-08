package tui

import "time"

type ViewID int

const (
	ViewScan ViewID = iota
	ViewResults
)

type switchViewMsg struct {
	view ViewID
}
type tickMsg time.Time
