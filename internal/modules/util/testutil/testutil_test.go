package testutil_test

import (
	"testing"

	"github.com/hardbox-io/hardbox/internal/modules"
	"github.com/hardbox-io/hardbox/internal/modules/util/testutil"
)

func TestAssertStatus(t *testing.T) {
	findings := []modules.Finding{
		{
			Check:   modules.Check{ID: "chk-001"},
			Status:  modules.StatusCompliant,
			Current: "enabled",
			Detail:  "check passed",
		},
		{
			Check:   modules.Check{ID: "chk-002"},
			Status:  modules.StatusNonCompliant,
			Current: "disabled",
			Detail:  "check failed",
		},
	}

	// Should pass without logging errors
	testutil.AssertStatus(t, findings, "chk-001", modules.StatusCompliant)
	testutil.AssertStatus(t, findings, "chk-002", modules.StatusNonCompliant)
}
