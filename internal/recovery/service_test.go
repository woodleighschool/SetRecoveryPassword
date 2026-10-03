package recovery

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/woodleighschool/jamf-recovery-lock/internal/config"
	"github.com/woodleighschool/jamf-recovery-lock/internal/jamf"
	"github.com/woodleighschool/jamf-recovery-lock/internal/state"
)

type memoryStore struct {
	entries  map[int]*state.Entry
	failSave bool
	failAt   int
	attempts int
	saves    int
}

func clone(e *state.Entry) *state.Entry {
	if e == nil {
		return nil
	}
	v := *e
	if e.Password != nil {
		p := *e.Password
		v.Password = &p
	}
	return &v
}
func (m *memoryStore) Get(_ context.Context, id int) (*state.Entry, error) {
	return clone(m.entries[id]), nil
}
func (m *memoryStore) Save(_ context.Context, e *state.Entry) error {
	m.attempts++
	if m.failSave || m.failAt == m.attempts {
		return errors.New("database unavailable")
	}
	m.entries[e.ID] = clone(e)
	m.saves++
	return nil
}

type fakeJamf struct {
	preflightErr             error
	history                  []jamf.Command
	devices                  []jamf.Device
	password, status, detail string
	queues                   int
	queueErr                 error
	commandErr               error
}

func (j *fakeJamf) Computers(context.Context, string) ([]jamf.Device, error) { return j.devices, nil }
func (j *fakeJamf) Commands(context.Context, jamf.Device) ([]jamf.Command, error) {
	return j.history, j.preflightErr
}

func (j *fakeJamf) Password(context.Context, jamf.Device) (string, error) { return j.password, nil }
func (j *fakeJamf) Queue(_ context.Context, _ jamf.Device, p string) (string, error) {
	j.queues++
	if j.queueErr != nil {
		return "", j.queueErr
	}
	j.password = p
	return "rotation-uuid", nil
}
func (j *fakeJamf) Command(context.Context, jamf.Device, string) (jamf.Command, error) {
	return jamf.Command{Status: j.status, Detail: j.detail}, j.commandErr
}

type fakeSecrets struct {
	password         string
	creates, updates int
	err              error
}

func (o *fakeSecrets) GetSecret(context.Context, string) (string, error) { return o.password, o.err }
func (o *fakeSecrets) CreateSecret(_ context.Context, _ jamf.Device, p string) (string, error) {
	o.creates++
	if o.err != nil {
		return "", o.err
	}
	o.password = p
	return "item-id", nil
}
func (o *fakeSecrets) UpdateSecret(_ context.Context, _ string, p string) error {
	o.updates++
	if o.err != nil {
		return o.err
	}
	o.password = p
	return nil
}

func fixture(e *state.Entry) (*Service, *memoryStore, *fakeJamf, *fakeSecrets) {
	store := &memoryStore{entries: map[int]*state.Entry{}}
	if e != nil {
		store.entries[1] = clone(e)
	}
	j := &fakeJamf{devices: []jamf.Device{{ID: 1, ManagementID: "management-id"}}, password: "confirmed", status: "pending"}
	op := &fakeSecrets{password: "confirmed"}
	svc := &Service{Store: store, Jamf: j, Secrets: op, Config: &config.Config{PasswordLength: 10, RotationAge: 31 * 24 * time.Hour, PendingAge: 7 * 24 * time.Hour}, Logger: slog.New(slog.DiscardHandler)}
	return svc, store, j, op
}
func pendingEntry(now time.Time) *state.Entry {
	p := "candidate"
	return &state.Entry{ID: 1, Password: &p, OPUUID: "existing-item", Phase: state.Pending, CommandUUID: "rotation-uuid", RequestedAt: &now, Date: now.Add(-40 * 24 * time.Hour).Format(time.UnixDate)}
}

func TestCandidatePromotionRequiresAcknowledgementAndMatchingPassword(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, status, password string
		promote                bool
	}{
		{"pending with matching inventory", "pending", "candidate", false},
		{"acknowledged but inventory stale", "acknowledged", "confirmed", false},
		{"unknown command with matching inventory", "unknown", "candidate", false},
		{"acknowledged and matching", "acknowledged", "candidate", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, store, j, op := fixture(pendingEntry(now))
			j.status = tc.status
			j.password = tc.password
			result, err := svc.reconcile(t.Context(), j.devices[0], now)
			if err != nil {
				t.Fatal(err)
			}
			if tc.promote {
				if result != "promoted" || op.password != "candidate" || store.entries[1].Password != nil || store.entries[1].Phase != state.Stable {
					t.Fatalf("candidate not promoted correctly: %s", result)
				}
			} else {
				if result != "pending" || op.password != "confirmed" || store.entries[1].Password == nil {
					t.Fatalf("unconfirmed candidate changed secret: %s", result)
				}
			}
			if j.queues != 0 {
				t.Fatal("pending rotation requeued")
			}
		})
	}
}

func TestFailedCommandRemainsBlockedAcrossRuns(t *testing.T) {
	now := time.Now().UTC()
	svc, store, j, op := fixture(pendingEntry(now))
	j.status = "failed"
	j.detail = "The provided recovery password failed to validate."
	result, err := svc.reconcile(t.Context(), j.devices[0], now)
	if err == nil || result != "blocked" || store.entries[1].Phase != state.Blocked {
		t.Fatal("failed command not blocked")
	}
	j.status = "acknowledged"
	j.password = "candidate"
	_, err = svc.reconcile(t.Context(), j.devices[0], now.Add(20*24*time.Hour))
	if err == nil || j.queues != 0 || op.password != "confirmed" || store.entries[1].Password == nil {
		t.Fatal("failed command silently retried or promoted")
	}
}

func TestPropagationRecoversAfterOverdueAlert(t *testing.T) {
	requested := time.Now().Add(-10 * 24 * time.Hour)
	svc, _, j, op := fixture(pendingEntry(requested))
	j.status = "acknowledged"
	_, err := svc.reconcile(t.Context(), j.devices[0], time.Now())
	if err == nil || j.queues != 0 || op.updates != 0 {
		t.Fatal("overdue pending command must alert without rotation")
	}
	j.password = "candidate"
	result, err := svc.reconcile(t.Context(), j.devices[0], time.Now())
	if err != nil || result != "promoted" || op.updates != 1 {
		t.Fatalf("propagation did not recover: %s %v", result, err)
	}
}

func TestSubmissionRequiresDurableCandidate(t *testing.T) {
	now := time.Now().UTC()
	svc, store, j, _ := fixture(nil)
	store.failSave = true
	_, err := svc.reconcile(t.Context(), j.devices[0], now)
	if err == nil || j.queues != 0 {
		t.Fatal("command queued without durable candidate")
	}
	store.failSave = false
	j.queueErr = errors.New("acceptance unknown")
	_, err = svc.reconcile(t.Context(), j.devices[0], now)
	if err == nil || store.entries[1].Phase != state.Blocked || store.entries[1].Password == nil {
		t.Fatal("uncertain submission lost durable candidate")
	}
	_, _ = svc.reconcile(t.Context(), j.devices[0], now)
	if j.queues != 1 {
		t.Fatal("uncertain submission requeued")
	}
}

func TestUncorrelatedRowsWithoutCommandEvidenceNeverQueue(t *testing.T) {
	now := time.Now().UTC()
	for _, phase := range []string{state.Prepared, state.Blocked, "corrupt"} {
		t.Run(phase, func(t *testing.T) {
			e := pendingEntry(now)
			e.Phase = phase
			e.CommandUUID = ""
			svc, _, j, op := fixture(e)
			j.password = "candidate"
			j.status = "acknowledged"
			_, err := svc.reconcile(t.Context(), j.devices[0], now)
			if err == nil || j.queues != 0 || op.updates != 0 {
				t.Fatal("uncertain legacy/prepared state changed remote systems")
			}
		})
	}
}

func TestStableMismatchBlocksBeforeRotation(t *testing.T) {
	now := time.Now().UTC()
	e := &state.Entry{ID: 1, OPUUID: "item-id", Phase: state.Stable, Date: now.Add(-40 * 24 * time.Hour).Format(time.UnixDate)}
	svc, store, j, op := fixture(e)
	j.password = "incorrect"
	_, err := svc.reconcile(t.Context(), j.devices[0], now)
	if err == nil || j.queues != 0 || store.entries[1].Phase != state.Blocked || op.password != "confirmed" {
		t.Fatal("mismatched current password was rotated")
	}
}

func TestDryRunHasNoWritesInAnyPhase(t *testing.T) {
	now := time.Now().UTC()
	for _, phase := range []string{"new", state.Stable, state.Pending, state.Prepared, state.Blocked} {
		t.Run(phase, func(t *testing.T) {
			e := pendingEntry(now)
			e.Phase = phase
			switch phase {
			case "new":
				e = nil
			case state.Stable:
				e.Password = nil
				e.Date = now.Add(-40 * 24 * time.Hour).Format(time.RFC3339)
			}
			svc, store, j, op := fixture(e)
			svc.Config.DryRun = true
			j.status = "acknowledged"
			if phase == state.Pending {
				j.password = "candidate"
			}
			_, _ = svc.reconcile(t.Context(), j.devices[0], now)
			if store.saves != 0 || j.queues != 0 || op.creates != 0 || op.updates != 0 {
				t.Fatal("dry run changed state")
			}
		})
	}
}

func TestFailedSecretPromotionRetainsCandidateAndMapping(t *testing.T) {
	now := time.Now().UTC()
	svc, store, j, op := fixture(pendingEntry(now))
	j.status = "acknowledged"
	j.password = "candidate"
	op.err = errors.New("vault unavailable")
	_, err := svc.reconcile(t.Context(), j.devices[0], now)
	if err == nil || store.entries[1].Password == nil || store.entries[1].OPUUID != "existing-item" {
		t.Fatal("failed promotion lost state")
	}
	op.err = nil
	result, err := svc.reconcile(t.Context(), j.devices[0], now)
	if err != nil || result != "promoted" || j.queues != 0 {
		t.Fatalf("secret retry did not recover: %s %v", result, err)
	}
}

func TestRunContinuesAndReportsFailures(t *testing.T) {
	svc, store, j, _ := fixture(nil)
	store.entries[1] = &state.Entry{ID: 1, Phase: state.Blocked, LastError: "failed validation"}
	j.devices = append(j.devices, jamf.Device{ID: 2})
	summary, err := svc.Run(t.Context())
	if err == nil || summary.Failed != 1 || summary.Blocked != 1 || summary.Queued != 1 || store.entries[2].Phase != state.Pending {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
}

func TestPasswordGenerationPreservesLengthAndAlphabet(t *testing.T) {
	for _, length := range []int{1, 10, 32} {
		p, err := generatePassword(length)
		if err != nil || len(p) != length || strings.Trim(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
			t.Fatalf("password properties failed at length %d", length)
		}
	}
	if _, err := generatePassword(0); err == nil {
		t.Fatal("accepted empty credential")
	}
}

func TestPreflightReadFailureAndExternalPendingDoNotBlockState(t *testing.T) {
	for _, mode := range []string{"read outage", "external pending"} {
		t.Run(mode, func(t *testing.T) {
			svc, store, j, _ := fixture(nil)
			if mode == "read outage" {
				j.preflightErr = errors.New("history unavailable")
			} else {
				j.history = []jamf.Command{{UUID: "external", Status: "pending"}}
			}
			_, err := svc.reconcile(t.Context(), j.devices[0], time.Now())
			if err == nil || store.saves != 0 || j.queues != 0 {
				t.Fatal("preflight failure changed state")
			}
			j.preflightErr = nil
			j.history = nil
			result, err := svc.reconcile(t.Context(), j.devices[0], time.Now())
			if err != nil || result != "queued" {
				t.Fatalf("preflight could not recover: %s %v", result, err)
			}
		})
	}
}

func TestQueuedCommandPersistenceFailureNeverResubmits(t *testing.T) {
	svc, store, j, _ := fixture(nil)
	store.failAt = 2
	_, err := svc.reconcile(t.Context(), j.devices[0], time.Now())
	if err == nil || j.queues != 1 || store.entries[1].Phase != state.Prepared {
		t.Fatal("queued submission lost preparation")
	}
	store.failAt = 0
	_, err = svc.reconcile(t.Context(), j.devices[0], time.Now())
	if err == nil || j.queues != 1 || store.entries[1].Phase != state.Blocked {
		t.Fatal("queued command replayed after persistence failure")
	}
}

func TestSecretWritePersistenceFailureRetriesPromotionWithoutRotation(t *testing.T) {
	for _, create := range []bool{false, true} {
		t.Run(map[bool]string{false: "update", true: "create"}[create], func(t *testing.T) {
			now := time.Now().UTC()
			e := pendingEntry(now)
			if create {
				e.OPUUID = ""
			}
			svc, store, j, op := fixture(e)
			j.status = "acknowledged"
			j.password = "candidate"
			store.failAt = 1
			_, err := svc.reconcile(t.Context(), j.devices[0], now)
			if err == nil || op.password != "candidate" || store.entries[1].Password == nil {
				t.Fatal("promotion save failure lost candidate")
			}
			store.failAt = 0
			result, err := svc.reconcile(t.Context(), j.devices[0], now)
			if err != nil || result != "promoted" || j.queues != 0 || store.entries[1].Password != nil {
				t.Fatalf("promotion could not recover: %s %v", result, err)
			}
		})
	}
}

func TestEmptyCandidateCannotBePromoted(t *testing.T) {
	now := time.Now().UTC()
	e := pendingEntry(now)
	p := ""
	e.Password = &p
	svc, store, j, op := fixture(e)
	j.status = "acknowledged"
	j.password = ""
	_, err := svc.reconcile(t.Context(), j.devices[0], now)
	if err == nil || op.updates != 0 || store.entries[1].Phase != state.Blocked {
		t.Fatal("empty candidate promoted")
	}
}

func TestUncorrelatedCandidateRecoversFromSuccessfulSettledHistory(t *testing.T) {
	now := time.Now().UTC()
	for _, phase := range []string{state.Prepared, state.Blocked, state.Pending} {
		t.Run(phase, func(t *testing.T) {
			e := pendingEntry(now)
			e.Phase = phase
			e.CommandUUID = ""
			e.RequestedAt = nil
			svc, store, j, op := fixture(e)
			j.password = "candidate"
			j.history = []jamf.Command{{UUID: "completed", Type: "SET_RECOVERY_LOCK", Status: "acknowledged", SentAt: now.Add(-time.Hour)}}
			result, err := svc.reconcile(t.Context(), j.devices[0], now)
			if err != nil || result != "promoted" || store.entries[1].Phase != state.Stable || store.entries[1].CommandUUID != "completed" || store.entries[1].RequestedAt == nil || op.password != "candidate" || j.queues != 0 {
				t.Fatalf("result=%s err=%v", result, err)
			}
		})
	}
}

func TestUncorrelatedCandidateRequiresSettledMatchingLatestSetCommand(t *testing.T) {
	now := time.Now().UTC()
	completed := jamf.Command{UUID: "completed", Type: "SET_RECOVERY_LOCK", Status: "acknowledged", SentAt: now.Add(-time.Hour)}
	for _, tc := range []struct {
		name, password string
		history        []jamf.Command
		pending        bool
	}{
		{name: "pending despite matching inventory", password: "candidate", history: []jamf.Command{{UUID: "waiting", Type: "SET_RECOVERY_LOCK", Status: "pending", SentAt: now.Add(-time.Minute)}}, pending: true},
		{name: "older pending cannot overwrite after promotion", password: "candidate", history: []jamf.Command{completed, {UUID: "waiting", Type: "SET_RECOVERY_LOCK", Status: "pending", SentAt: now.Add(-2 * time.Hour)}}, pending: true},
		{name: "unknown command", password: "candidate", history: []jamf.Command{{UUID: "unknown", Type: "SET_RECOVERY_LOCK", Status: "unknown", SentAt: now}}, pending: true},
		{name: "failed latest command", password: "candidate", history: []jamf.Command{completed, {UUID: "failed", Type: "SET_RECOVERY_LOCK", Status: "failed", SentAt: now}}},
		{name: "different reported password", password: "other", history: []jamf.Command{completed}, pending: true},
		{name: "no set history", password: "candidate"},
		{name: "verification acknowledgement is not password proof", password: "candidate", history: []jamf.Command{{UUID: "verify", Type: "VERIFY_RECOVERY_LOCK", Status: "acknowledged", SentAt: now}}},
		{name: "missing submission time", password: "candidate", history: []jamf.Command{{UUID: "completed", Type: "SET_RECOVERY_LOCK", Status: "acknowledged"}}},
		{name: "ambiguous newest command", password: "candidate", history: []jamf.Command{completed, {UUID: "other", Type: "SET_RECOVERY_LOCK", Status: "acknowledged", SentAt: completed.SentAt}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := pendingEntry(now)
			e.Phase = state.Blocked
			e.CommandUUID = ""
			e.RequestedAt = nil
			e.Date = now.Add(-time.Hour).Format(time.RFC3339)
			svc, store, j, op := fixture(e)
			j.password = tc.password
			j.history = tc.history
			result, err := svc.reconcile(t.Context(), j.devices[0], now)
			if tc.pending {
				if result != "pending" || err != nil {
					t.Fatalf("result=%s err=%v", result, err)
				}
			} else if result != "blocked" || err == nil {
				t.Fatalf("result=%s err=%v", result, err)
			}
			if op.updates != 0 || op.creates != 0 || j.queues != 0 || store.entries[1].Password == nil || store.entries[1].CommandUUID != "" {
				t.Fatal("uncorrelated candidate changed a secret or queued a rotation")
			}
		})
	}
}

func TestUncorrelatedCandidateRetriesEvidenceAndPersistsBeforePromotion(t *testing.T) {
	now := time.Now().UTC()
	e := pendingEntry(now)
	e.Phase = state.Prepared
	e.CommandUUID = ""
	requested := now.Add(-2 * time.Minute)
	e.RequestedAt = &requested
	svc, store, j, op := fixture(e)
	j.preflightErr = errors.New("history unavailable")
	if _, err := svc.reconcile(t.Context(), j.devices[0], now); err == nil || store.saves != 0 {
		t.Fatal("history outage changed durable state")
	}
	j.preflightErr = nil
	j.history = []jamf.Command{{UUID: "completed", Type: "SET_RECOVERY_LOCK", Status: "acknowledged", SentAt: now.Add(-time.Minute)}}
	j.password = "candidate"
	store.failSave = true
	if _, err := svc.reconcile(t.Context(), j.devices[0], now); err == nil || op.updates != 0 {
		t.Fatal("promotion started without durable command evidence")
	}
	store.failSave = false
	result, err := svc.reconcile(t.Context(), j.devices[0], now)
	if err != nil || result != "promoted" || j.queues != 0 {
		t.Fatalf("result=%s err=%v", result, err)
	}
}

func TestPreparedCandidateCannotAdoptAnEarlierRotation(t *testing.T) {
	now := time.Now().UTC()
	e := pendingEntry(now)
	e.Phase = state.Prepared
	e.CommandUUID = ""
	svc, _, j, op := fixture(e)
	j.password = "candidate"
	j.history = []jamf.Command{{UUID: "earlier", Type: "SET_RECOVERY_LOCK", Status: "acknowledged", SentAt: now.Add(-time.Hour)}}
	if _, err := svc.reconcile(t.Context(), j.devices[0], now); err == nil || op.updates != 0 || j.queues != 0 {
		t.Fatal("earlier command used to confirm a newer candidate")
	}
}

func TestUncorrelatedDryRunAndPromotionRetryPreserveCandidate(t *testing.T) {
	now := time.Now().UTC()
	e := pendingEntry(now)
	e.Phase = state.Blocked
	e.CommandUUID = ""
	e.RequestedAt = nil
	svc, store, j, op := fixture(e)
	j.password = "candidate"
	j.history = []jamf.Command{{UUID: "completed", Type: "SET_RECOVERY_LOCK", Status: "acknowledged", SentAt: now.Add(-time.Minute)}}
	svc.Config.DryRun = true
	result, err := svc.reconcile(t.Context(), j.devices[0], now)
	if err != nil || result != "would-change" || store.saves != 0 || op.updates != 0 || j.queues != 0 {
		t.Fatalf("dry run result=%s err=%v", result, err)
	}
	svc.Config.DryRun = false
	op.err = errors.New("vault unavailable")
	j.status = "acknowledged"
	if _, err := svc.reconcile(t.Context(), j.devices[0], now); err == nil || store.entries[1].Password == nil || store.entries[1].CommandUUID != "completed" {
		t.Fatal("failed secret write lost recovered command evidence")
	}
	op.err = nil
	result, err = svc.reconcile(t.Context(), j.devices[0], now)
	if err != nil || result != "promoted" || j.queues != 0 {
		t.Fatalf("retry result=%s err=%v", result, err)
	}
}

func TestUncorrelatedCandidateRechecksFailedEvidenceOnLaterRuns(t *testing.T) {
	now := time.Now().UTC()
	e := pendingEntry(now)
	e.Phase = state.Blocked
	e.CommandUUID = ""
	e.RequestedAt = nil
	svc, store, j, op := fixture(e)
	j.history = []jamf.Command{{UUID: "failed", Type: "SET_RECOVERY_LOCK", Status: "failed", SentAt: now.Add(-time.Hour)}}
	if _, err := svc.reconcile(t.Context(), j.devices[0], now); err == nil || store.entries[1].CommandUUID != "" || op.updates != 0 {
		t.Fatal("failed evidence incorrectly confirmed a candidate")
	}
	j.history = []jamf.Command{{UUID: "repaired", Type: "SET_RECOVERY_LOCK", Status: "acknowledged", SentAt: now}}
	j.password = "candidate"
	result, err := svc.reconcile(t.Context(), j.devices[0], now.Add(time.Hour))
	if err != nil || result != "promoted" || j.queues != 0 {
		t.Fatalf("result=%s err=%v", result, err)
	}
}
