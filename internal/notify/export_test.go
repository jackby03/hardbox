// Copyright (C) 2024 Jack (jackby03)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
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

