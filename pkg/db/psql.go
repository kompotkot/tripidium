package db

import (
	"context"
	"errors"
	"time"

	"github.com/kompotkot/tripidium/pkg/iam"

	"github.com/jackc/pgx/v5"
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

// GetUser retrieves user from the database by it's Id or Email
func (p *PsqlDB) GetUser(ctx context.Context, userId int64, email string) (iam.User, error) {
	var user iam.User
	var err error

	if userId != 0 {
		query := `SELECT id, username, password_hash, created_at, updated_at FROM users WHERE id = $1`

		err = p.pool.QueryRow(ctx, query, userId).Scan(
			&user.Id,
			&user.Username,
			&user.PasswordHash,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
	}
	if email != "" {
		query := `SELECT id, username, password_hash, created_at, updated_at FROM users WHERE username = $1`

		err = p.pool.QueryRow(ctx, query, email).Scan(
			&user.Id,
			&user.Username,
			&user.PasswordHash,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return iam.User{}, ErrUserNotFound
	}
	if err != nil {
		return iam.User{}, err
	}

	return user, nil
}

func (p *PsqlDB) GetToken(ctx context.Context, tokenId int64) (iam.Token, error) {
	query := `SELECT id, user_id, is_revoked, issued_at, expires_at, updated_at FROM tokens WHERE id = $1`

	var token iam.Token
	err := p.pool.QueryRow(ctx, query, tokenId).Scan(
		&token.Id,
		&token.UserId,
		&token.IsRevoked,
		&token.IssuedAt,
		&token.ExpiresAt,
		&token.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return iam.Token{}, ErrTokenNotFound
	}
	if err != nil {
		return iam.Token{}, err
	}

	return token, err
}
