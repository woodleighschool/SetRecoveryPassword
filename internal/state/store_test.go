package state

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func testDatabase(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("RECOVERY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set RECOVERY_TEST_DATABASE_URL to an isolated local PostgreSQL database")
	}
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("recovery_test_%d", time.Now().UnixNano())
	if _, err = conn.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, "SET search_path TO "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, cleanupErr := conn.Exec(cleanupCtx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); cleanupErr != nil {
			t.Error(cleanupErr)
		}
		if closeErr := conn.Close(cleanupCtx); closeErr != nil {
			t.Error(closeErr)
		}
	})
	return conn
}

func TestMigrationPreservesLegacyStateAndIsIdempotent(t *testing.T) {
	conn := testDatabase(t)
	ctx := t.Context()
	_, err := conn.Exec(ctx, `CREATE TABLE recovery_password_state (
 id INTEGER PRIMARY KEY,password TEXT,password_opuuid TEXT,date TEXT NOT NULL,grace_ticker INTEGER);
 INSERT INTO recovery_password_state VALUES
 (1,NULL,'stable-item','Thu Oct  1 00:00:00 UTC 2026',NULL),
 (2,'candidate','existing-item','Thu Oct  1 00:00:00 UTC 2026',2),
 (3,'initial-candidate',NULL,'Thu Oct  1 00:00:00 UTC 2026',NULL),
 (4,NULL,NULL,'Thu Oct  1 00:00:00 UTC 2026',NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = Migrate(ctx, conn); err != nil {
			t.Fatal(err)
		}
	}
	store := &Store{conn: conn}
	stable, err := store.Get(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if stable.Phase != Stable || stable.OPUUID != "stable-item" || stable.Password != nil || stable.Date != "Thu Oct  1 00:00:00 UTC 2026" {
		t.Fatalf("stable metadata changed: %+v", stable)
	}
	for _, id := range []int{2, 3, 4} {
		e, getErr := store.Get(ctx, id)
		if getErr != nil {
			t.Fatal(getErr)
		}
		if e.Phase != Blocked || e.LastError == "" {
			t.Fatalf("legacy row %d not blocked", id)
		}
		if id == 2 && (e.Password == nil || *e.Password != "candidate" || e.OPUUID != "existing-item") {
			t.Fatal("legacy candidate/mapping lost")
		}
	}
	requested := time.Now().UTC().Truncate(time.Microsecond)
	p := "new-candidate"
	entry := &Entry{ID: 1, Password: &p, OPUUID: "stable-item", Date: stable.Date, Phase: Pending, CommandUUID: "command-id", RequestedAt: &requested}
	if err = store.Save(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if err = Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	persisted, err := store.Get(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Phase != Pending || *persisted.Password != p || persisted.CommandUUID != entry.CommandUUID || !persisted.RequestedAt.Equal(requested) {
		t.Fatal("migration changed new pending state")
	}
	entry.Password = nil
	entry.Phase = Stable
	entry.Date = requested.Format(time.RFC3339)
	if err = store.Save(ctx, entry); err != nil {
		t.Fatal(err)
	}
	persisted, err = store.Get(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Password != nil || persisted.OPUUID != "stable-item" || persisted.CommandUUID != "command-id" {
		t.Fatal("promotion lost item mapping or retained candidate")
	}
}

func TestDryReadSupportsLegacyAndFreshSchemaWithoutMigration(t *testing.T) {
	conn := testDatabase(t)
	ctx := t.Context()
	store := &Store{conn: conn}
	e, err := store.Get(ctx, 1)
	if err != nil || e != nil {
		t.Fatalf("fresh dry read: %v", err)
	}
	_, err = conn.Exec(ctx, `CREATE TABLE recovery_password_state(id INTEGER PRIMARY KEY,password TEXT,password_opuuid TEXT,date TEXT NOT NULL,grace_ticker INTEGER);
 INSERT INTO recovery_password_state VALUES(1,'candidate','item','legacy-date',7);`)
	if err != nil {
		t.Fatal(err)
	}
	e, err = store.Get(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if e.Phase != Blocked || e.Password == nil || e.OPUUID != "item" || !strings.Contains(e.LastError, "legacy") {
		t.Fatal("legacy dry read not classified safely")
	}
	var columns int
	err = conn.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='recovery_password_state'`).Scan(&columns)
	if err != nil || columns != 5 {
		t.Fatalf("dry read modified schema: %d %v", columns, err)
	}
}

func TestSessionLockExcludesConcurrentRunsAndReleasesOnClose(t *testing.T) {
	second := testDatabase(t)
	first, err := pgx.Connect(t.Context(), os.Getenv("RECOVERY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close(context.Background()) })
	ctx := t.Context()
	var acquired bool
	if err := first.QueryRow(ctx, "SELECT pg_try_advisory_lock(748293601)").Scan(&acquired); err != nil || !acquired {
		t.Fatalf("first lock: %v", err)
	}
	if err := second.QueryRow(ctx, "SELECT pg_try_advisory_lock(748293601)").Scan(&acquired); err != nil || acquired {
		t.Fatalf("second lock: acquired=%v err=%v", acquired, err)
	}
	if err := first.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.QueryRow(ctx, "SELECT pg_try_advisory_lock(748293601)").Scan(&acquired); err != nil || !acquired {
		t.Fatalf("released lock: %v", err)
	}
}
