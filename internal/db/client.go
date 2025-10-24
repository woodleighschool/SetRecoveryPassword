package db

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/woodleighschool/SetRecoveryPassword/internal/config"
)

type Client interface {
	GetEntry(int) (*Entry, error)
	CreateEntry(*Entry) error
	UpdateEntryPassword(*Entry) error
	UpdateEntryTouch(*Entry) error
	UpdateEntryMigrate(*Entry) error
	UpdateEntryDecay(*Entry) error
	Close() error
}

type dbClient struct {
	connection *pgx.Conn
}

type Entry struct {
	ID          *int    `db:"id,omitempty"`
	Password    *string `db:"password,omitempty"`
	OPUUID      *string `db:"password_opuuid,omitempty"`
	Date        *string `db:"date,omitempty"`
	GraceTicker *int    `db:"grace_ticker,omitempty"`
}

func NewClient(cfg *config.Config, logger *slog.Logger) (Client, error) {
	conn, err := pgx.Connect(context.Background(), fmt.Sprintf("postgres://%s:%s@%s:%s/setrecoverypassword", cfg.DatabaseUsername, cfg.DatabasePassword, cfg.DatabaseHost, cfg.DatabasePort))
	if err != nil {
		return nil, fmt.Errorf("unable to connect to Postgres instance: %w", err)
	}

	conn.Exec(context.Background(), `
	CREATE TABLE IF NOT EXISTS recovery_password_state (
		id INTEGER PRIMARY KEY,
		password TEXT,
		password_opuuid TEXT,
		date TEXT NOT NULL,
		grace_ticker INTEGER
	);`)

	return &dbClient{
		connection: conn,
	}, nil
}

func (d *dbClient) GetEntry(id int) (*Entry, error) {
	row, _ := d.connection.Query(context.Background(), "select id, password, date, password_opuuid, grace_ticker FROM recovery_password_state WHERE id = $1", id)
	entry, err := pgx.CollectOneRow(row, pgx.RowToStructByName[Entry])
	if err == pgx.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("unable to get data from database: %w", err)
	} else {
		return &entry, nil
	}
}

func (d *dbClient) CreateEntry(entry *Entry) error {
	_, err := d.connection.Exec(context.Background(), "INSERT INTO recovery_password_state (id, password, date) VALUES ($1, $2, $3)", entry.ID, entry.Password, entry.Date)
	if err != nil {
		return fmt.Errorf("an error occured inserting data in the database: %w", err)
	} else {
		return nil
	}
}

func (d *dbClient) UpdateEntryPassword(entry *Entry) error {
	_, err := d.connection.Exec(context.Background(), "UPDATE recovery_password_state SET password = $1, date = $2, grace_ticker = NULL WHERE id = $3", entry.Password, entry.Date, entry.ID)
	if err != nil {
		return fmt.Errorf("unable to update data in database: %w", err)
	} else {
		return nil
	}
}

func (d *dbClient) UpdateEntryTouch(entry *Entry) error {
	_, err := d.connection.Exec(context.Background(), "UPDATE recovery_password_state SET date = $1, grace_ticker = $2 WHERE id = $3", entry.Date, entry.GraceTicker, entry.ID)
	if err != nil {
		return fmt.Errorf("unable to update data in database: %w", err)
	} else {
		return nil
	}
}

func (d *dbClient) UpdateEntryMigrate(entry *Entry) error {
	_, err := d.connection.Exec(context.Background(), "UPDATE recovery_password_state SET password = NULL, password_opuuid = $1, grace_ticker = NULL WHERE id = $2", entry.OPUUID, entry.ID)
	if err != nil {
		return fmt.Errorf("unable to update data in database: %w", err)
	} else {
		return nil
	}
}

func (d *dbClient) UpdateEntryDecay(entry *Entry) error {
	_, err := d.connection.Exec(context.Background(), "UPDATE recovery_password_state SET date = $1 WHERE id = $2", entry.Date, entry.ID)
	if err != nil {
		return fmt.Errorf("unable to update data in database: %w", err)
	} else {
		return nil
	}
}

func (d *dbClient) Close() error {
	err := d.connection.Close(context.Background())
	if err != nil {
		return fmt.Errorf("unable to close db connection: %w", err)
	} else {
		return nil
	}
}
