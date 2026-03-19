//go:build psql

package psql

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	db "github.com/kompotkot/tripidium/pkg/db"
	"github.com/kompotkot/tripidium/pkg/iam"

	"github.com/google/uuid"
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

func (p *PsqlDB) CreateUser(ctx context.Context, userID uuid.UUID, isActive bool, username, email, passwordHash string, phone int) (iam.User, error) {
	const query = `
		INSERT INTO users (id, is_active, username, email, password_hash, phone)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, is_active, username, email, phone, password_hash, created_at, updated_at
	`

	var user iam.User
	err := p.pool.QueryRow(ctx, query, userID, isActive, username, email, passwordHash, phone).Scan(
		&user.ID,
		&user.IsActive,
		&user.Username,
		&user.Email,
		&user.Phone,
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

// GetUser retrieves user from the database by it's ID or Username
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
		&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.User{}, db.ErrUserNotFound
		}

		return iam.User{}, err
	}

	return user, nil
}

// CreateAuthSession creates a session after login
func (p *PsqlDB) CreateAuthSession(ctx context.Context, userID uuid.UUID, refreshTokenHash, clientIP, userAgent string) (iam.AuthSession, error) {
	const defaultSessionTTL = 30 * 24 * time.Hour
	createdIP := net.ParseIP(clientIP)
	if createdIP == nil {
		createdIP = net.IP{}
	}
	var ua *string
	if userAgent != "" {
		ua = &userAgent
	}
	expiresAt := time.Now().UTC().Add(defaultSessionTTL)

	const query = `
		INSERT INTO auth_sessions (user_id, refresh_token_hash, created_ip, created_user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, user_id, refresh_token_hash, created_ip, created_user_agent, revoke_reason, revoked_at, created_at, expires_at, replaced_by
	`
	var s iam.AuthSession
	err := p.pool.QueryRow(ctx, query, userID, refreshTokenHash, createdIP, ua, expiresAt).Scan(
		&s.ID, &s.UserID, &s.RefreshTokenHash, &s.CreatedIP, &s.CreatedUserAgent,
		&s.RevokeReason, &s.RevokedAt, &s.CreatedAt, &s.ExpiresAt, &s.ReplacedBy,
	)
	if err != nil {
		return iam.AuthSession{}, err
	}
	return s, nil
}

func (p *PsqlDB) UpdateUser(ctx context.Context, userID uuid.UUID, username, email, phone string) (iam.User, error) {
	return iam.User{}, nil
}

func (p *PsqlDB) UpdateUserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	return nil
}

func (p *PsqlDB) GetAuthSession(ctx context.Context, sessionID uuid.UUID) (iam.AuthSession, error) {
	return iam.AuthSession{}, nil
}

func (p *PsqlDB) GetAuthSessionByRefreshToken(ctx context.Context, refreshTokenHash string) (iam.AuthSession, error) {
	return iam.AuthSession{}, nil
}

func (p *PsqlDB) ListAuthSessions(ctx context.Context, userID uuid.UUID) ([]iam.AuthSession, error) {
	return nil, nil
}

func (p *PsqlDB) RevokeAuthSession(ctx context.Context, sessionID uuid.UUID, reason string, replacedBy *uuid.UUID) error {
	return nil
}

func (p *PsqlDB) RevokeAllAuthSessions(ctx context.Context, userID uuid.UUID) error {
	return nil
}
