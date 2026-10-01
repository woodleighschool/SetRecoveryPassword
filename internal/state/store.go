package state

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/woodleighschool/jamf-recovery-lock/internal/config"
)

const (
	Stable   = "stable"
	Prepared = "prepared"
	Pending  = "pending"
	Blocked  = "blocked"
)

// Entry retains the existing candidate password and 1Password item mapping.
// Candidate passwords never represent confirmed secrets until promotion succeeds.
type Entry struct {
	ID          int
	Password    *string
	OPUUID      string
	Date        string
	Phase       string
	CommandUUID string
	RequestedAt *time.Time
	LastError   string
}

type Store struct{ conn *pgx.Conn }

// Migrate keeps the deployed table identity and upgrades it atomically.
// Old candidates have no trustworthy command correlation and require review.
func Migrate(ctx context.Context, conn *pgx.Conn) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin state migration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
 CREATE TABLE IF NOT EXISTS recovery_password_state (
 id INTEGER PRIMARY KEY, password TEXT, password_opuuid TEXT, date TEXT NOT NULL
 );
 ALTER TABLE recovery_password_state ADD COLUMN IF NOT EXISTS phase TEXT;
 ALTER TABLE recovery_password_state ADD COLUMN IF NOT EXISTS command_uuid TEXT;
 ALTER TABLE recovery_password_state ADD COLUMN IF NOT EXISTS requested_at TIMESTAMPTZ;
 ALTER TABLE recovery_password_state ADD COLUMN IF NOT EXISTS last_error TEXT;
 UPDATE recovery_password_state SET
 phase = CASE WHEN password IS NULL AND password_opuuid IS NOT NULL THEN 'stable' ELSE 'blocked' END,
 last_error = CASE WHEN password IS NOT NULL THEN 'legacy candidate has no command UUID; review Jamf command history before repair'
 WHEN password_opuuid IS NULL THEN 'legacy row has neither a candidate nor a 1Password mapping' ELSE NULL END
 WHERE phase IS NULL;
 ALTER TABLE recovery_password_state ALTER COLUMN phase SET NOT NULL;
 ALTER TABLE recovery_password_state DROP COLUMN IF EXISTS grace_ticker;
 `)
	if err != nil {
		return fmt.Errorf("migrate recovery state: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit state migration: %w", err)
	}
	return nil
}

func New(ctx context.Context, cfg *config.Config, dryRun bool) (*Store, error) {
	u := url.URL{Scheme: "postgres", Host: net.JoinHostPort(cfg.DatabaseHost, strconv.Itoa(cfg.DatabasePort)), Path: "/setrecoverypassword", User: url.UserPassword(cfg.DatabaseUsername, cfg.DatabasePassword)}
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		return nil, fmt.Errorf("connect recovery state: %w", err)
	}
	s := &Store{conn: conn}
	ok := false
	defer func() {
		if !ok {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = conn.Close(closeCtx)
		}
	}()
	// A dedicated session lock prevents an overlapping manual run from queuing
	// the same rotation. PostgreSQL releases it when the session closes.
	var locked bool
	if err = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(748293601)").Scan(&locked); err != nil {
		return nil, fmt.Errorf("lock recovery run: %w", err)
	}
	if !locked {
		return nil, fmt.Errorf("another recovery run owns the state lock")
	}
	if !dryRun {
		if err = Migrate(ctx, conn); err != nil {
			return nil, err
		}
	}
	ok = true
	return s, nil
}

func (s *Store) Get(ctx context.Context, id int) (*Entry, error) {
	var e Entry
	// to_jsonb also reads the pre-migration schema in a genuinely read-only dry run.
	err := s.conn.QueryRow(ctx, `SELECT id, password, COALESCE(password_opuuid,''), date,
 COALESCE(to_jsonb(s)->>'phase',CASE WHEN password IS NULL AND password_opuuid IS NOT NULL THEN 'stable' ELSE 'blocked' END),
 COALESCE(to_jsonb(s)->>'command_uuid',''),(to_jsonb(s)->>'requested_at')::timestamptz,
 COALESCE(to_jsonb(s)->>'last_error',CASE WHEN password IS NOT NULL THEN 'legacy candidate has no command UUID; review Jamf command history before repair' ELSE '' END)
 FROM recovery_password_state s WHERE id=$1`, id).Scan(&e.ID, &e.Password, &e.OPUUID, &e.Date, &e.Phase, &e.CommandUUID, &e.RequestedAt, &e.LastError)
	var pgErr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == "42P01") {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read recovery state: %w", err)
	}
	return &e, nil
}

func (s *Store) Save(ctx context.Context, e *Entry) error {
	_, err := s.conn.Exec(ctx, `INSERT INTO recovery_password_state (id,password,password_opuuid,date,phase,command_uuid,requested_at,last_error)
 VALUES($1,$2,NULLIF($3,''),$4,$5,NULLIF($6,''),$7,NULLIF($8,''))
 ON CONFLICT(id) DO UPDATE SET password=EXCLUDED.password,password_opuuid=EXCLUDED.password_opuuid,date=EXCLUDED.date,
 phase=EXCLUDED.phase,command_uuid=EXCLUDED.command_uuid,requested_at=EXCLUDED.requested_at,last_error=EXCLUDED.last_error`,
		e.ID, e.Password, e.OPUUID, e.Date, e.Phase, e.CommandUUID, e.RequestedAt, e.LastError)
	if err != nil {
		return fmt.Errorf("save recovery state: %w", err)
	}
	return nil
}

func (s *Store) Close(ctx context.Context) error { return s.conn.Close(ctx) }
