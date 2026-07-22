package shells_test
import ("context";"testing";"github.com/hardbox-io/hardbox/internal/modules";"github.com/hardbox-io/hardbox/internal/modules/shells")
func TestModuleInterface(t *testing.T) { var m modules.Module = &shells.Module{}; if m.Name()=="" || m.Version()=="" { t.Error("incomplete") } }
func TestAuditFindings(t *testing.T) { m := &shells.Module{}; f, _ := m.Audit(context.Background(), nil); if len(f) != 5 { t.Errorf("got %d, want 5", len(f)) } }
func TestPlanChanges(t *testing.T) { m := &shells.Module{}; c, _ := m.Plan(context.Background(), nil); for _, ch := range c { if ch.Description=="" { t.Error("no desc") } } }
func TestChecks(t *testing.T) { for _, c := range []modules.Check{shells.CheckSHL001(),shells.CheckSHL002(),shells.CheckSHL003(),shells.CheckSHL004(),shells.CheckSHL005()} { if c.ID=="" || c.Title=="" { t.Errorf("incomplete %+v", c) } } }
