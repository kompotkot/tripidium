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
	"github.com/kompotkot/tripidium/pkg/model"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PsqlDB struct {
	pool *pgxpool.Pool
}

func NewPsqlDB(uri string, maxConns int, connMaxLifetime time.Duration) (*PsqlDB, error) {
	pool, err := pgxpool.New(context.Background(), uri)
	if err != nil {
		return nil, err
	}

	pool.Config().MaxConns = int32(maxConns)
	pool.Config().MaxConnLifetime = connMaxLifetime

	return &PsqlDB{pool: pool}, nil
}

func (p *PsqlDB) TestConnection(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return p.pool.Ping(ctx)
}

func (p *PsqlDB) Close() error {
	if p.pool != nil {
		p.pool.Close()
	}
	return nil
}

func (p *PsqlDB) CreateUser(ctx context.Context, userID uuid.UUID, isActive bool, username, email, passwordHash string, phone int) (model.User, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return model.User{}, err
	}
	defer tx.Rollback(ctx)

	const subjectQuery = `
		INSERT INTO subjects (id, kind)
		VALUES ($1, 'user')
	`
	if _, err := tx.Exec(ctx, subjectQuery, userID); err != nil {
		return model.User{}, err
	}

	const query = `
		INSERT INTO users (id, is_active, username, email, password_hash, phone)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, 0))
		RETURNING id, is_active, username, email, phone, password_hash, created_at, updated_at
	`

	var user model.User
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
			return model.User{}, db.ErrUnexpectedEmptyReturn
		}

		// Handle the username uniqueness error
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // unique_violation
				return model.User{}, db.ErrUserAlreadyExists
			}
		}

		return model.User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.User{}, err
	}

	return user, nil
}

func (p *PsqlDB) GetUser(ctx context.Context, userID, username, email string) (model.User, error) {
	const baseQuery = `
		SELECT id, is_active, username, email, phone, password_hash, created_at, updated_at
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
		return model.User{}, fmt.Errorf("GetUser: at least one filter must be provided")
	}

	query := baseQuery + " WHERE " + strings.Join(conditions, " AND ") + " AND is_active = true"

	var user model.User
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
			return model.User{}, db.ErrUserNotFound
		}
		return model.User{}, err
	}

	return user, nil
}

// CreateAuthSession creates a session after login
func (p *PsqlDB) CreateAuthSession(ctx context.Context, sessionID uuid.UUID, subjectID, familyID uuid.UUID, refreshTokenHash, createdIP string, createdUserAgent *string, expiresAt time.Time) (model.AuthSession, error) {
	const query = `
		INSERT INTO auth_sessions (id, subject_id, family_id, refresh_token_hash, created_ip, created_user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, subject_id, (SELECT kind FROM subjects WHERE subjects.id = auth_sessions.subject_id), family_id, refresh_token_hash, created_ip, created_user_agent, revoke_reason, revoked_at, created_at, expires_at, replaced_by
	`
	var as model.AuthSession
	err := p.pool.QueryRow(ctx, query, sessionID, subjectID, familyID, refreshTokenHash, createdIP, createdUserAgent, expiresAt).Scan(
		&as.ID, &as.SubjectID, &as.SubjectKind, &as.FamilyID, &as.RefreshTokenHash, &as.CreatedIP, &as.CreatedUserAgent,
		&as.RevokeReason, &as.RevokedAt, &as.CreatedAt, &as.ExpiresAt, &as.ReplacedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.AuthSession{}, db.ErrUnexpectedEmptyReturn
		}

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			// subject_id references subjects(id) foreign_key_violation
			if pgErr.Code == "23503" {
				return model.AuthSession{}, db.ErrUserNotFound
			}
		}

		return model.AuthSession{}, err
	}
	return as, nil
}

func (p *PsqlDB) UpdateUser(ctx context.Context, userID uuid.UUID, username, email, phone string) (model.User, error) {
	phoneNumber := 0
	if strings.TrimSpace(phone) != "" {
		parsedPhone, err := strconv.Atoi(phone)
		if err != nil {
			return model.User{}, fmt.Errorf("failed to parse phone: %w", err)
		}
		phoneNumber = parsedPhone
	}

	const query = `
		UPDATE users
		SET username = $2, email = $3, phone = NULLIF($4, 0)
		WHERE id = $1 AND is_active = true
		RETURNING id, is_active, username, email, phone, password_hash, created_at, updated_at
	`

	var user model.User
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
			return model.User{}, db.ErrUserNotFound
		}

		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // unique_violation
				return model.User{}, db.ErrUserAlreadyExists
			}
		}

		return model.User{}, err
	}
	return user, nil
}

func (p *PsqlDB) UpdateUserPassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	const query = `
		UPDATE users
		SET password_hash = $2
		WHERE id = $1 AND is_active = true
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

func (p *PsqlDB) DeactivateUser(ctx context.Context, userID uuid.UUID) error {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	const deactivateQuery = `
		UPDATE users
		SET is_active = false
		WHERE id = $1 AND is_active = true
	`
	tag, err := tx.Exec(ctx, deactivateQuery, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return db.ErrUserNotFound
	}

	const revokeSessionsQuery = `
		UPDATE auth_sessions
		SET revoked_at = NOW(), revoke_reason = 'user_deactivated'
		WHERE subject_id = $1 AND revoked_at IS NULL
	`
	if _, err := tx.Exec(ctx, revokeSessionsQuery, userID); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (p *PsqlDB) CreateUserRegistrationInvite(ctx context.Context, id string, description *string) error {
	const query = `
		INSERT INTO user_invites (id, description)
		VALUES ($1, $2)
	`
	_, err := p.pool.Exec(ctx, query, id, description)
	return err
}

func (p *PsqlDB) CheckUserInvite(ctx context.Context, inviteCode string) (bool, error) {
	const query = `
		SELECT EXISTS (SELECT 1 FROM user_invites WHERE id = $1 AND user_id IS NULL)
	`
	var exists bool
	err := p.pool.QueryRow(ctx, query, inviteCode).Scan(&exists)
	return exists, err
}

func (p *PsqlDB) ClaimUserInvite(ctx context.Context, inviteCode string, userID uuid.UUID) error {
	const query = `
		UPDATE user_invites
		SET user_id = $2
		WHERE id = $1
	`
	_, err := p.pool.Exec(ctx, query, inviteCode, userID)
	return err
}

func (p *PsqlDB) GetAuthSession(ctx context.Context, sessionID uuid.UUID) (model.AuthSession, error) {
	const query = `
		SELECT a.id, a.subject_id, s.kind, a.family_id, a.refresh_token_hash, a.created_ip, a.created_user_agent, a.revoke_reason, a.revoked_at, a.created_at, a.expires_at, a.replaced_by
		FROM auth_sessions a
		JOIN subjects s ON s.id = a.subject_id
		WHERE a.id = $1
	`

	var as model.AuthSession
	err := p.pool.QueryRow(ctx, query, sessionID).Scan(
		&as.ID, &as.SubjectID, &as.SubjectKind, &as.FamilyID, &as.RefreshTokenHash, &as.CreatedIP, &as.CreatedUserAgent,
		&as.RevokeReason, &as.RevokedAt, &as.CreatedAt, &as.ExpiresAt, &as.ReplacedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.AuthSession{}, db.ErrTokenNotFound
		}
		return model.AuthSession{}, err
	}
	return as, nil
}

func (p *PsqlDB) GetAuthSessionByRefreshToken(ctx context.Context, refreshTokenHash string) (model.AuthSession, error) {
	const query = `
		SELECT a.id, a.subject_id, s.kind, a.family_id, a.refresh_token_hash, a.created_ip, a.created_user_agent, a.revoke_reason, a.revoked_at, a.created_at, a.expires_at, a.replaced_by
		FROM auth_sessions a
		JOIN subjects s ON s.id = a.subject_id
		WHERE a.refresh_token_hash = $1
	`

	var as model.AuthSession
	err := p.pool.QueryRow(ctx, query, refreshTokenHash).Scan(
		&as.ID, &as.SubjectID, &as.SubjectKind, &as.FamilyID, &as.RefreshTokenHash, &as.CreatedIP, &as.CreatedUserAgent,
		&as.RevokeReason, &as.RevokedAt, &as.CreatedAt, &as.ExpiresAt, &as.ReplacedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.AuthSession{}, db.ErrTokenNotFound
		}
		return model.AuthSession{}, err
	}
	return as, nil
}

func (p *PsqlDB) RefreshAuthSession(ctx context.Context, oldRefreshTokenHash string, newSessionID uuid.UUID, newRefreshTokenHash, createdIP string, createdUserAgent *string, expiresAt time.Time) (model.AuthSession, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return model.AuthSession{}, err
	}
	defer tx.Rollback(ctx)

	const selectForUpdateQuery = `
		SELECT a.id, a.subject_id, s.kind, a.family_id, a.refresh_token_hash, a.created_ip, a.created_user_agent, a.revoke_reason, a.revoked_at, a.created_at, a.expires_at, a.replaced_by
		FROM auth_sessions a
		JOIN subjects s ON s.id = a.subject_id
		WHERE a.refresh_token_hash = $1
		FOR UPDATE
	`

	var oldSession model.AuthSession
	err = tx.QueryRow(ctx, selectForUpdateQuery, oldRefreshTokenHash).Scan(
		&oldSession.ID, &oldSession.SubjectID, &oldSession.SubjectKind, &oldSession.FamilyID, &oldSession.RefreshTokenHash, &oldSession.CreatedIP, &oldSession.CreatedUserAgent,
		&oldSession.RevokeReason, &oldSession.RevokedAt, &oldSession.CreatedAt, &oldSession.ExpiresAt, &oldSession.ReplacedBy,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.AuthSession{}, db.ErrTokenNotFound
		}
		return model.AuthSession{}, err
	}

	// Check if the session is revoked

	if oldSession.RevokedAt != nil {
		const revokeFamilyQuery = `
			UPDATE auth_sessions
			SET revoked_at = NOW(), revoke_reason = 'reuse_detected'
			WHERE family_id = $1 AND revoked_at IS NULL
		`
		if _, err = tx.Exec(ctx, revokeFamilyQuery, oldSession.FamilyID); err != nil {
			return model.AuthSession{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			return model.AuthSession{}, err
		}
		return model.AuthSession{}, db.ErrTokenReuseDetected
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
			return model.AuthSession{}, err
		}
		if err = tx.Commit(ctx); err != nil {
			return model.AuthSession{}, err
		}
		return model.AuthSession{}, db.ErrTokenExpired
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
			return model.AuthSession{}, db.ErrUserNotFound
		}
		return model.AuthSession{}, err
	}
	if !isUserActive {
		return model.AuthSession{}, db.ErrUserNotFound
	}

	// Step 1: Revoke the old session without setting replaced_by yet.
	// replaced_by references auth_sessions(id), so the new session must exist first.
	// Revoking here clears the unique partial index (family_id WHERE revoked_at IS NULL)
	// so the subsequent INSERT does not violate uq_auth_sess_family_active.

	const revokeRotatedQuery = `
		UPDATE auth_sessions
		SET revoked_at = NOW(), revoke_reason = 'rotated'
		WHERE id = $1 AND revoked_at IS NULL
	`
	tag, err := tx.Exec(ctx, revokeRotatedQuery, oldSession.ID)
	if err != nil {
		return model.AuthSession{}, err
	}
	if tag.RowsAffected() != 1 {
		return model.AuthSession{}, db.ErrTokenNotFound
	}

	// Step 2: Insert the new session. The family slot is now free.

	const createNewSessionQuery = `
		INSERT INTO auth_sessions (id, subject_id, family_id, refresh_token_hash, created_ip, created_user_agent, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, subject_id, (SELECT kind FROM subjects WHERE subjects.id = auth_sessions.subject_id), family_id, refresh_token_hash, created_ip, created_user_agent, revoke_reason, revoked_at, created_at, expires_at, replaced_by
	`
	var newSession model.AuthSession
	err = tx.QueryRow(ctx, createNewSessionQuery, newSessionID, oldSession.SubjectID, oldSession.FamilyID, newRefreshTokenHash, createdIP, createdUserAgent, expiresAt).Scan(
		&newSession.ID, &newSession.SubjectID, &newSession.SubjectKind, &newSession.FamilyID, &newSession.RefreshTokenHash, &newSession.CreatedIP, &newSession.CreatedUserAgent,
		&newSession.RevokeReason, &newSession.RevokedAt, &newSession.CreatedAt, &newSession.ExpiresAt, &newSession.ReplacedBy,
	)
	if err != nil {
		return model.AuthSession{}, err
	}

	// Step 3: Back-fill replaced_by on the old session now that the new row exists.

	const backfillReplacedByQuery = `
		UPDATE auth_sessions
		SET replaced_by = $2
		WHERE id = $1
	`
	if _, err = tx.Exec(ctx, backfillReplacedByQuery, oldSession.ID, newSessionID); err != nil {
		return model.AuthSession{}, err
	}

	if err = tx.Commit(ctx); err != nil {
		return model.AuthSession{}, err
	}

	return newSession, nil
}

func (p *PsqlDB) ListAuthSessions(ctx context.Context, subjectID uuid.UUID) ([]model.AuthSession, error) {
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

	sessions := make([]model.AuthSession, 0)
	for rows.Next() {
		var as model.AuthSession
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
	const query = `
		UPDATE auth_sessions
		SET revoked_at = NOW(), revoke_reason = 'logout'
		WHERE subject_id = $1 AND revoked_at IS NULL
	`
	_, err := p.pool.Exec(ctx, query, subjectID)
	return err
}

func (p *PsqlDB) GetSubject(ctx context.Context, subjectID uuid.UUID) (model.Subject, error) {
	const query = `
		SELECT id, kind, created_at, updated_at
		FROM subjects
		WHERE id = $1
	`
	var s model.Subject
	err := p.pool.QueryRow(ctx, query, subjectID).Scan(
		&s.ID, &s.Kind, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.Subject{}, db.ErrSubjectNotFound
		}
		return model.Subject{}, err
	}
	return s, nil
}

func (p *PsqlDB) CreateOrganization(ctx context.Context, orgID uuid.UUID, name string, description *string, ownerUserID uuid.UUID) (model.Organization, error) {
	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return model.Organization{}, err
	}
	defer tx.Rollback(ctx)

	const checkOwnerQuery = `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND is_active = true)`
	var ownerActive bool
	if err := tx.QueryRow(ctx, checkOwnerQuery, ownerUserID).Scan(&ownerActive); err != nil {
		return model.Organization{}, err
	}
	if !ownerActive {
		return model.Organization{}, db.ErrUserNotFound
	}

	const subjectQuery = `INSERT INTO subjects (id, kind) VALUES ($1, 'organization')`
	if _, err := tx.Exec(ctx, subjectQuery, orgID); err != nil {
		return model.Organization{}, err
	}

	const orgQuery = `
		INSERT INTO organizations (id, name, description)
		VALUES ($1, $2, $3)
		RETURNING id, name, description, created_at, updated_at
	`
	var org model.Organization
	if err := tx.QueryRow(ctx, orgQuery, orgID, name, description).Scan(
		&org.ID, &org.Name, &org.Description, &org.CreatedAt, &org.UpdatedAt,
	); err != nil {
		return model.Organization{}, err
	}

	const memberQuery = `
		INSERT INTO organization_members (user_id, organization_id, role)
		VALUES ($1, $2, 'owner')
	`
	if _, err := tx.Exec(ctx, memberQuery, ownerUserID, orgID); err != nil {
		return model.Organization{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.Organization{}, err
	}
	return org, nil
}

func (p *PsqlDB) GetOrganization(ctx context.Context, orgID, memberUserID uuid.UUID) (model.Organization, error) {
	const query = `
		SELECT o.id, o.name, o.description, o.created_at, o.updated_at
		FROM organizations o
		JOIN organization_members m ON m.organization_id = o.id
		JOIN users u ON u.id = m.user_id AND u.is_active = true
		WHERE o.id = $1 AND m.user_id = $2
	`
	var org model.Organization
	err := p.pool.QueryRow(ctx, query, orgID, memberUserID).Scan(
		&org.ID, &org.Name, &org.Description, &org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.Organization{}, db.ErrOrganizationNotFound
		}
		return model.Organization{}, err
	}
	return org, nil
}

func (p *PsqlDB) GetOrganizationByID(ctx context.Context, orgID uuid.UUID) (model.Organization, error) {
	const query = `
		SELECT id, name, description, created_at, updated_at
		FROM organizations
		WHERE id = $1
	`
	var org model.Organization
	err := p.pool.QueryRow(ctx, query, orgID).Scan(
		&org.ID, &org.Name, &org.Description, &org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.Organization{}, db.ErrOrganizationNotFound
		}
		return model.Organization{}, err
	}
	return org, nil
}

func (p *PsqlDB) ListOrganizations(ctx context.Context, userID uuid.UUID) ([]model.Organization, error) {
	const query = `
		SELECT o.id, o.name, o.description, o.created_at, o.updated_at
		FROM organizations o
		JOIN organization_members m ON m.organization_id = o.id
		JOIN users u ON u.id = m.user_id AND u.is_active = true
		WHERE m.user_id = $1
		ORDER BY o.created_at DESC
	`
	rows, err := p.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	orgs := make([]model.Organization, 0)
	for rows.Next() {
		var org model.Organization
		if err := rows.Scan(&org.ID, &org.Name, &org.Description, &org.CreatedAt, &org.UpdatedAt); err != nil {
			return nil, err
		}
		orgs = append(orgs, org)
	}
	return orgs, rows.Err()
}

func (p *PsqlDB) UpdateOrganization(ctx context.Context, orgID, memberUserID uuid.UUID, name *string, description *string) (model.Organization, error) {
	const query = `
		UPDATE organizations o
		SET
			name = COALESCE($2, name),
			description = COALESCE($3, description)
		FROM organization_members m
		JOIN users u ON u.id = m.user_id AND u.is_active = true
		WHERE o.id = $1 AND m.organization_id = o.id AND m.user_id = $4
		RETURNING o.id, o.name, o.description, o.created_at, o.updated_at
	`
	var org model.Organization
	err := p.pool.QueryRow(ctx, query, orgID, name, description, memberUserID).Scan(
		&org.ID, &org.Name, &org.Description, &org.CreatedAt, &org.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.Organization{}, db.ErrOrganizationNotFound
		}
		return model.Organization{}, err
	}
	return org, nil
}

func (p *PsqlDB) DeleteOrganization(ctx context.Context, orgID, memberUserID uuid.UUID) error {
	const query = `
		DELETE FROM subjects s
		WHERE s.id = $1
			AND s.kind = 'organization'
			AND EXISTS (
				SELECT 1
				FROM organization_members m
				JOIN users u ON u.id = m.user_id AND u.is_active = true
				WHERE m.organization_id = s.id AND m.user_id = $2
			)
	`
	tag, err := p.pool.Exec(ctx, query, orgID, memberUserID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return db.ErrOrganizationNotFound
	}
	return nil
}

func (p *PsqlDB) ListOrganizationMembers(ctx context.Context, orgID, memberUserID uuid.UUID) ([]model.OrganizationMember, error) {
	const query = `
		SELECT m.user_id, m.organization_id, m.role, m.created_at, m.updated_at
		FROM organization_members m
		JOIN organization_members caller ON caller.organization_id = m.organization_id
		JOIN users u ON u.id = caller.user_id AND u.is_active = true
		WHERE m.organization_id = $1 AND caller.user_id = $2
		ORDER BY m.created_at
	`
	rows, err := p.pool.Query(ctx, query, orgID, memberUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	members := make([]model.OrganizationMember, 0)
	for rows.Next() {
		var m model.OrganizationMember
		if err := rows.Scan(&m.UserID, &m.OrganizationID, &m.Role, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

func (p *PsqlDB) AddOrganizationMember(ctx context.Context, orgID, userID, memberUserID uuid.UUID, role string) (model.OrganizationMember, error) {
	const query = `
		INSERT INTO organization_members (user_id, organization_id, role)
		SELECT target.id, $2, $3
		FROM users target
		JOIN organization_members caller ON caller.organization_id = $2 AND caller.user_id = $4
		JOIN users caller_user ON caller_user.id = caller.user_id AND caller_user.is_active = true
		WHERE target.id = $1 AND target.is_active = true
		RETURNING user_id, organization_id, role, created_at, updated_at
	`
	var m model.OrganizationMember
	err := p.pool.QueryRow(ctx, query, userID, orgID, role, memberUserID).Scan(
		&m.UserID, &m.OrganizationID, &m.Role, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// No row: either the target user does not exist or is inactive
			return model.OrganizationMember{}, db.ErrUserNotFound
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505": // unique_violation
				return model.OrganizationMember{}, db.ErrOrganizationMemberAlreadyExists
			case "23503": // foreign_key_violation (org does not exist)
				return model.OrganizationMember{}, db.ErrUserNotFound
			}
		}
		return model.OrganizationMember{}, err
	}
	return m, nil
}

func (p *PsqlDB) GetOrganizationMember(ctx context.Context, orgID, userID, memberUserID uuid.UUID) (model.OrganizationMember, error) {
	const query = `
		SELECT m.user_id, m.organization_id, m.role, m.created_at, m.updated_at
		FROM organization_members m
		JOIN users target_user ON target_user.id = m.user_id AND target_user.is_active = true
		JOIN organization_members caller ON caller.organization_id = m.organization_id
		JOIN users caller_user ON caller_user.id = caller.user_id AND caller_user.is_active = true
		WHERE m.user_id = $1 AND m.organization_id = $2 AND caller.user_id = $3
	`
	var m model.OrganizationMember
	err := p.pool.QueryRow(ctx, query, userID, orgID, memberUserID).Scan(
		&m.UserID, &m.OrganizationID, &m.Role, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.OrganizationMember{}, db.ErrOrganizationMemberNotFound
		}
		return model.OrganizationMember{}, err
	}
	return m, nil
}

func (p *PsqlDB) UpdateOrganizationMemberRole(ctx context.Context, orgID, userID, memberUserID uuid.UUID, role string) (model.OrganizationMember, error) {
	const query = `
		UPDATE organization_members m
		SET role = $3
		FROM organization_members caller
		JOIN users u ON u.id = caller.user_id AND u.is_active = true
		WHERE m.user_id = $1
			AND m.organization_id = $2
			AND caller.organization_id = m.organization_id
			AND caller.user_id = $4
		RETURNING m.user_id, m.organization_id, m.role, m.created_at, m.updated_at
	`
	var m model.OrganizationMember
	err := p.pool.QueryRow(ctx, query, userID, orgID, role, memberUserID).Scan(
		&m.UserID, &m.OrganizationID, &m.Role, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return model.OrganizationMember{}, db.ErrOrganizationMemberNotFound
		}
		return model.OrganizationMember{}, err
	}
	return m, nil
}

func (p *PsqlDB) RemoveOrganizationMember(ctx context.Context, orgID, userID, memberUserID uuid.UUID) error {
	const query = `
		DELETE FROM organization_members m
		USING organization_members caller
		JOIN users u ON u.id = caller.user_id AND u.is_active = true
		WHERE m.user_id = $1
			AND m.organization_id = $2
			AND caller.organization_id = m.organization_id
			AND caller.user_id = $3
	`
	tag, err := p.pool.Exec(ctx, query, userID, orgID, memberUserID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return db.ErrOrganizationMemberNotFound
	}
	return nil
}
