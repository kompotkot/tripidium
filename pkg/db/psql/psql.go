//go:build psql

package psql

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return iam.User{}, err
	}
	defer tx.Rollback(ctx)

	const subjectQuery = `
		INSERT INTO subjects (id, kind)
		VALUES ($1, 'user')
	`
	if _, err := tx.Exec(ctx, subjectQuery, userID); err != nil {
		return iam.User{}, err
	}

	const query = `
		INSERT INTO users (id, is_active, username, email, password_hash, phone)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, 0))
		RETURNING id, is_active, username, email, COALESCE(phone, 0), password_hash, created_at, updated_at
	`

	var user iam.User
	err = tx.QueryRow(ctx, query, userID, isActive, username, email, passwordHash, phone).Scan(
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
	if err := tx.Commit(ctx); err != nil {
		return iam.User{}, err
	}

	return user, nil
}

// GetUser retrieves user from the database by ID, username, or email.
func (p *PsqlDB) GetUser(ctx context.Context, userID, username, email string) (iam.User, error) {
	const baseQuery = `
		SELECT id, is_active, username, email, COALESCE(phone, 0), password_hash, created_at, updated_at
		FROM users
	`

	conditions := make([]string, 0, 3)
	args := make([]any, 0, 3)

	if userID != "" {
		args = append(args, userID)
		conditions = append(conditions, fmt.Sprintf("id = $%d", len(args)))
	}
	if username != "" {
		args = append(args, username)
		conditions = append(conditions, fmt.Sprintf("username = $%d", len(args)))
	}
	if email != "" {
		args = append(args, email)
		conditions = append(conditions, fmt.Sprintf("email = $%d", len(args)))
	}

	if len(conditions) == 0 {
		return iam.User{}, fmt.Errorf("GetUser: at least one filter must be provided")
	}

	query := baseQuery + " WHERE " + strings.Join(conditions, " AND ")

	var user iam.User
	err := p.pool.QueryRow(ctx, query, args...).Scan(
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
			return iam.User{}, db.ErrUserNotFound
		}
		return iam.User{}, err
	}

	return user, nil
}

// CreateAuthSession creates a session after login
func (p *PsqlDB) CreateAuthSession(ctx context.Context, sessionID uuid.UUID, subjectID, familyID uuid.UUID, refreshTokenHash, createdIP string, createdUserAgent *string, expiresAt time.Time) (iam.AuthSession, error) {
	const query = `
		INSERT INTO auth_sessions (id, subject_id, family_id, refresh_token_hash, created_ip, created_user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, subject_id, (SELECT kind FROM subjects WHERE subjects.id = auth_sessions.subject_id), family_id, refresh_token_hash, created_ip, created_user_agent, revoke_reason, revoked_at, created_at, expires_at, replaced_by
	`
	var as iam.AuthSession
	err := p.pool.QueryRow(ctx, query, sessionID, subjectID, familyID, refreshTokenHash, createdIP, createdUserAgent, expiresAt).Scan(
		&as.ID, &as.SubjectID, &as.SubjectKind, &as.FamilyID, &as.RefreshTokenHash, &as.CreatedIP, &as.CreatedUserAgent,
		&as.RevokeReason, &as.RevokedAt, &as.CreatedAt, &as.ExpiresAt, &as.ReplacedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.AuthSession{}, db.ErrUnexpectedEmptyReturn
		}

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			// subject_id references subjects(id) foreign_key_violation
			if pgErr.Code == "23503" {
				return iam.AuthSession{}, db.ErrUserNotFound
			}
		}

		return iam.AuthSession{}, err
	}
	return as, nil
}

func (p *PsqlDB) UpdateUser(ctx context.Context, userID uuid.UUID, username, email, phone string) (iam.User, error) {
	phoneNumber := 0
	if strings.TrimSpace(phone) != "" {
		parsedPhone, err := strconv.Atoi(phone)
		if err != nil {
			return iam.User{}, fmt.Errorf("failed to parse phone: %w", err)
		}
		phoneNumber = parsedPhone
	}

	const query = `
		UPDATE users
		SET username = $2, email = $3, phone = NULLIF($4, 0)
		WHERE id = $1
		RETURNING id, is_active, username, email, COALESCE(phone, 0), password_hash, created_at, updated_at
	`

	var user iam.User
	err := p.pool.QueryRow(ctx, query, userID, username, email, phoneNumber).Scan(
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
			return iam.User{}, db.ErrUserNotFound
		}

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

func (p *PsqlDB) UpdateUserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	const query = `
		UPDATE users
		SET password_hash = $2
		WHERE id = $1
	`
	tag, err := p.pool.Exec(ctx, query, userID, passwordHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return db.ErrUserNotFound
	}
	return nil
}

func (p *PsqlDB) CheckUserInvite(ctx context.Context, inviteCode string) (bool, error) {
	const query = `
		SELECT EXISTS (SELECT 1 FROM invites WHERE id = $1 AND user_id IS NULL)
	`
	var exists bool
	err := p.pool.QueryRow(ctx, query, inviteCode).Scan(&exists)
	return exists, err
}

func (p *PsqlDB) ClaimUserInvite(ctx context.Context, inviteCode string, userID uuid.UUID) error {
	const query = `
		UPDATE invites
		SET user_id = $2
		WHERE id = $1
	`
	_, err := p.pool.Exec(ctx, query, inviteCode, userID)
	return err
}

func (p *PsqlDB) GetAuthSession(ctx context.Context, sessionID uuid.UUID) (iam.AuthSession, error) {
	const query = `
		SELECT a.id, a.subject_id, s.kind, a.family_id, a.refresh_token_hash, a.created_ip, a.created_user_agent, a.revoke_reason, a.revoked_at, a.created_at, a.expires_at, a.replaced_by
		FROM auth_sessions a
		JOIN subjects s ON s.id = a.subject_id
		WHERE a.id = $1
	`

	var as iam.AuthSession
	err := p.pool.QueryRow(ctx, query, sessionID).Scan(
		&as.ID, &as.SubjectID, &as.SubjectKind, &as.FamilyID, &as.RefreshTokenHash, &as.CreatedIP, &as.CreatedUserAgent,
		&as.RevokeReason, &as.RevokedAt, &as.CreatedAt, &as.ExpiresAt, &as.ReplacedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.AuthSession{}, db.ErrTokenNotFound
		}
		return iam.AuthSession{}, err
	}
	return as, nil
}

func (p *PsqlDB) GetAuthSessionByRefreshToken(ctx context.Context, refreshTokenHash string) (iam.AuthSession, error) {
	const query = `
		SELECT a.id, a.subject_id, s.kind, a.family_id, a.refresh_token_hash, a.created_ip, a.created_user_agent, a.revoke_reason, a.revoked_at, a.created_at, a.expires_at, a.replaced_by
		FROM auth_sessions a
		JOIN subjects s ON s.id = a.subject_id
		WHERE a.refresh_token_hash = $1
	`

	var as iam.AuthSession
	err := p.pool.QueryRow(ctx, query, refreshTokenHash).Scan(
		&as.ID, &as.SubjectID, &as.SubjectKind, &as.FamilyID, &as.RefreshTokenHash, &as.CreatedIP, &as.CreatedUserAgent,
		&as.RevokeReason, &as.RevokedAt, &as.CreatedAt, &as.ExpiresAt, &as.ReplacedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.AuthSession{}, db.ErrTokenNotFound
		}
		return iam.AuthSession{}, err
	}
	return as, nil
}

func (p *PsqlDB) RefreshAuthSession(ctx context.Context, oldRefreshTokenHash string, newSessionID uuid.UUID, newRefreshTokenHash, createdIP string, createdUserAgent *string, expiresAt time.Time) (iam.AuthSession, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return iam.AuthSession{}, err
	}
	defer tx.Rollback(ctx)

	const selectForUpdateQuery = `
		SELECT a.id, a.subject_id, s.kind, a.family_id, a.refresh_token_hash, a.created_ip, a.created_user_agent, a.revoke_reason, a.revoked_at, a.created_at, a.expires_at, a.replaced_by
		FROM auth_sessions a
		JOIN subjects s ON s.id = a.subject_id
		WHERE a.refresh_token_hash = $1
		FOR UPDATE
	`

	var oldSession iam.AuthSession
	err = tx.QueryRow(ctx, selectForUpdateQuery, oldRefreshTokenHash).Scan(
		&oldSession.ID, &oldSession.SubjectID, &oldSession.SubjectKind, &oldSession.FamilyID, &oldSession.RefreshTokenHash, &oldSession.CreatedIP, &oldSession.CreatedUserAgent,
		&oldSession.RevokeReason, &oldSession.RevokedAt, &oldSession.CreatedAt, &oldSession.ExpiresAt, &oldSession.ReplacedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.AuthSession{}, db.ErrTokenNotFound
		}
		return iam.AuthSession{}, err
	}

	// Check if the session is revoked

	if oldSession.RevokedAt != nil {
		const revokeFamilyQuery = `
			UPDATE auth_sessions
			SET revoked_at = NOW(), revoke_reason = 'reuse_detected'
			WHERE family_id = $1 AND revoked_at IS NULL
		`
		if _, err = tx.Exec(ctx, revokeFamilyQuery, oldSession.FamilyID); err != nil {
			return iam.AuthSession{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			return iam.AuthSession{}, err
		}
		return iam.AuthSession{}, db.ErrTokenReuseDetected
	}

	// Check if the session is expired

	now := time.Now().UTC()
	if !oldSession.ExpiresAt.After(now) {
		const markExpiredQuery = `
			UPDATE auth_sessions
			SET revoked_at = NOW(), revoke_reason = 'expired'
			WHERE id = $1 AND revoked_at IS NULL
		`
		if _, err = tx.Exec(ctx, markExpiredQuery, oldSession.ID); err != nil {
			return iam.AuthSession{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			return iam.AuthSession{}, err
		}
		return iam.AuthSession{}, db.ErrTokenExpired
	}

	// Check if the user-backed subject is active

	const checkActiveUserQuery = `
		SELECT u.is_active
		FROM users u
		JOIN subjects s ON s.id = u.id
		WHERE u.id = $1
			AND s.kind = 'user'
	`
	var isUserActive bool
	err = tx.QueryRow(ctx, checkActiveUserQuery, oldSession.SubjectID).Scan(&isUserActive)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iam.AuthSession{}, db.ErrUserNotFound
		}
		return iam.AuthSession{}, err
	}
	if !isUserActive {
		return iam.AuthSession{}, db.ErrUserNotFound
	}

	// Create a new session

	const createNewSessionQuery = `
		INSERT INTO auth_sessions (id, subject_id, family_id, refresh_token_hash, created_ip, created_user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, subject_id, (SELECT kind FROM subjects WHERE subjects.id = auth_sessions.subject_id), family_id, refresh_token_hash, created_ip, created_user_agent, revoke_reason, revoked_at, created_at, expires_at, replaced_by
	`
	var newSession iam.AuthSession
	err = tx.QueryRow(ctx, createNewSessionQuery, newSessionID, oldSession.SubjectID, oldSession.FamilyID, newRefreshTokenHash, createdIP, createdUserAgent, expiresAt).Scan(
		&newSession.ID, &newSession.SubjectID, &newSession.SubjectKind, &newSession.FamilyID, &newSession.RefreshTokenHash, &newSession.CreatedIP, &newSession.CreatedUserAgent,
		&newSession.RevokeReason, &newSession.RevokedAt, &newSession.CreatedAt, &newSession.ExpiresAt, &newSession.ReplacedBy,
	)
	if err != nil {
		return iam.AuthSession{}, err
	}

	// Revoke the old session

	const revokeRotatedQuery = `
		UPDATE auth_sessions
		SET revoked_at = NOW(), revoke_reason = 'rotated', replaced_by = $2
		WHERE id = $1 AND revoked_at IS NULL
	`
	tag, err := tx.Exec(ctx, revokeRotatedQuery, oldSession.ID, newSessionID)
	if err != nil {
		return iam.AuthSession{}, err
	}
	if tag.RowsAffected() != 1 {
		return iam.AuthSession{}, db.ErrTokenNotFound
	}

	if err = tx.Commit(ctx); err != nil {
		return iam.AuthSession{}, err
	}

	return newSession, nil
}

func (p *PsqlDB) ListAuthSessions(ctx context.Context, subjectID uuid.UUID) ([]iam.AuthSession, error) {
	const query = `
		SELECT a.id, a.subject_id, s.kind, a.family_id, a.refresh_token_hash, a.created_ip, a.created_user_agent, a.revoke_reason, a.revoked_at, a.created_at, a.expires_at, a.replaced_by
		FROM auth_sessions a
		JOIN subjects s ON s.id = a.subject_id
		WHERE a.subject_id = $1
			AND a.revoked_at IS NULL
			AND a.expires_at > NOW()
		ORDER BY a.created_at DESC
	`

	rows, err := p.pool.Query(ctx, query, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := make([]iam.AuthSession, 0)
	for rows.Next() {
		var as iam.AuthSession
		if err := rows.Scan(
			&as.ID, &as.SubjectID, &as.SubjectKind, &as.FamilyID, &as.RefreshTokenHash, &as.CreatedIP, &as.CreatedUserAgent,
			&as.RevokeReason, &as.RevokedAt, &as.CreatedAt, &as.ExpiresAt, &as.ReplacedBy,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, as)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return sessions, nil
}

func (p *PsqlDB) RevokeAuthSession(ctx context.Context, sessionID, subjectID uuid.UUID, reason string, replacedBy *uuid.UUID) error {
	const query = `
		UPDATE auth_sessions
		SET
			revoked_at = COALESCE(revoked_at, NOW()),
			revoke_reason = COALESCE(revoke_reason, $2),
			replaced_by = COALESCE(replaced_by, $3)
		WHERE id = $1
			AND subject_id = $4
	`
	tag, err := p.pool.Exec(ctx, query, sessionID, reason, replacedBy, subjectID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return db.ErrTokenNotFound
	}
	return err
}

func (p *PsqlDB) RevokeAllAuthSessions(ctx context.Context, subjectID uuid.UUID) error {
	return nil
}
