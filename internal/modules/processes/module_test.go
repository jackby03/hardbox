package processes_test
import ("context";"testing";"github.com/hardbox-io/hardbox/internal/modules";"github.com/hardbox-io/hardbox/internal/modules/processes")
func TestModuleInterface(t *testing.T) { var m modules.Module = &processes.Module{}; if m.Name()=="" || m.Version()=="" { t.Error("incomplete") } }
func TestAuditFindings(t *testing.T) { m := &processes.Module{}; f, _ := m.Audit(context.Background(), nil); if len(f) != 5 { t.Errorf("got %d, want 5", len(f)) } }
func TestPlanChanges(t *testing.T) { m := &processes.Module{}; c, _ := m.Plan(context.Background(), nil); for _, ch := range c { if ch.Description=="" { t.Error("no desc") } } }
func TestChecks(t *testing.T) { for _, c := range []modules.Check{processes.CheckPRC001(),processes.CheckPRC002(),processes.CheckPRC003(),processes.CheckPRC004(),processes.CheckPRC005()} { if c.ID=="" || c.Title=="" { t.Errorf("incomplete %+v", c) } } }
