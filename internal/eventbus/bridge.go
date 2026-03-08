package eventbus

import tea "github.com/charmbracelet/bubbletea"

type BusEventMsg struct {
	Event Event
}
type Bridge struct {
	bus     *EventBus
	program *tea.Program
}

func NewBridge(bus *EventBus, program *tea.Program) *Bridge {
	return &Bridge{bus: bus, program: program}
}
func (b *Bridge) Start() {
	b.bus.SubscribeAll(func(event Event) {
		b.program.Send(BusEventMsg{Event: event})
	})
}
func (b *Bridge) Stop() {
	b.bus.Close()
}
