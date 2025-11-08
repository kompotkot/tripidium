//go:build psql

package psql

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	db "github.com/kompotkot/tripidium/pkg/db"
	"github.com/kompotkot/tripidium/pkg/iam"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PsqlDB represents a PostgreSQL database connection
type PsqlDB struct {
	pool *pgxpool.Pool
}

// NewPsqlDB creates a new PostgreSQL database connection
func NewPsqlDB(uri string, maxConns int, connMaxLifetime time.Duration) (*PsqlDB, error) {
	pool, err := pgxpool.New(context.Background(), uri)
	if err != nil {
		return nil, err
	}

	pool.Config().MaxConns = int32(maxConns)
	pool.Config().MaxConnLifetime = connMaxLifetime

	return &PsqlDB{pool: pool}, nil
}

// TestConnection tests the database connection with a timeout
func (p *PsqlDB) TestConnection(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return p.pool.Ping(ctx)
}

// Close closes the database connection pool
func (p *PsqlDB) Close() error {
	if p.pool != nil {
		p.pool.Close()
	}
	return nil
}

func (p *PsqlDB) CreateUser(ctx context.Context, username, passwordHash string) (iam.User, error) {
	const query = `
		INSERT INTO users (username, password_hash) 
		VALUES ($1, $2) 
		RETURNING id, username, password_hash, created_at, updated_at
	`

	var user iam.User
	err := p.pool.QueryRow(ctx, query, username, passwordHash).Scan(
		&user.Id,
		&user.Username,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.User{}, db.ErrUnexpectedEmptyReturn
		}

		// Handle the username uniqueness error
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // unique_violation
				return iam.User{}, db.ErrUserAlreadyExists
			}
		}

		return iam.User{}, err
	}

	return user, nil
}

// GetUser retrieves user from the database by it's Id or Username
func (p *PsqlDB) GetUser(ctx context.Context, userId, username string) (iam.User, error) {
	var sb strings.Builder
	args := make([]interface{}, 0, 2)

	sb.WriteString(`SELECT id, username, password_hash, created_at, updated_at FROM users `)

	sep := " WHERE "
	if userId != "" {
		sb.WriteString(sep)
		args = append(args, userId)
		sb.WriteString(fmt.Sprintf("id = $%d", len(args)))
		sep = " AND "
	}
	if username != "" {
		sb.WriteString(sep)
		args = append(args, username)
		sb.WriteString(fmt.Sprintf("username = $%d", len(args)))
	}

	query := sb.String()

	var user iam.User
	err := p.pool.QueryRow(ctx, query, args...).Scan(
		&user.Id, &user.Username, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.User{}, db.ErrUserNotFound
		}

		return iam.User{}, err
	}

	return user, nil
}

func (p *PsqlDB) GetToken(ctx context.Context, tokenId string) (iam.Token, error) {
	query := `SELECT id, user_id, is_revoked, issued_at, expires_at, updated_at FROM tokens WHERE id = $1`

	var token iam.Token
	err := p.pool.QueryRow(ctx, query, tokenId).Scan(
		&token.Id, &token.UserId, &token.IsRevoked, &token.IssuedAt, &token.ExpiresAt, &token.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.Token{}, db.ErrTokenNotFound
		}

		return iam.Token{}, err
	}

	return token, err
}
