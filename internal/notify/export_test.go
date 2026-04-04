package notify

import "context"

// Exported shims for white-box testing.

var MatchesFilter = matchesFilter
var FormatSlackMessage = formatSlackMessage

// testAdapter is a fake adapter that records calls for test assertions.
type testAdapter struct {
	fn      func(AlertPayload) error
	matchFn func(EventType, string) bool
}

func (a *testAdapter) send(_ context.Context, p AlertPayload) error {
	return a.fn(p)
}

func (a *testAdapter) matches(event EventType, module string) bool {
	if a.matchFn != nil {
		return a.matchFn(event, module)
	}
	return true // match all by default
}

// NewMultiAlerterForTest returns a MultiAlerter wired to a custom send function.
// The adapter matches all events and modules, making it easy to observe dispatch.
func NewMultiAlerterForTest(sendFn func(AlertPayload) error) *MultiAlerter {
	return &MultiAlerter{
		adapters: []adapter{&testAdapter{fn: sendFn}},
	}
}
