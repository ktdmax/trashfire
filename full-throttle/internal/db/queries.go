package db

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/fullthrottle/platform/internal/models"
)

type Queries struct {
	db *sql.DB
}

func NewQueries(db *sql.DB) *Queries {
	return &Queries{db: db}
}

// ---- User Queries ----

func (q *Queries) GetUserByEmail(email string) (*models.User, error) {
	user := &models.User{}
	err := q.db.QueryRow(
		"SELECT id, email, password_hash, role, api_key, created_at, updated_at FROM users WHERE email = $1",
		email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role, &user.APIKey, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (q *Queries) CreateUser(email, passwordHash, role string) (*models.User, error) {
	user := &models.User{}
	err := q.db.QueryRow(
		"INSERT INTO users (email, password_hash, role, created_at, updated_at) VALUES ($1, $2, $3, $4, $4) RETURNING id, email, role, created_at",
		email, passwordHash, role, time.Now(),
	).Scan(&user.ID, &user.Email, &user.Role, &user.CreatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (q *Queries) ListUsers() ([]models.User, error) {
	// BUG-098: Password hashes and API keys included in user list query (CWE-200, CVSS 6.5, HIGH, Tier 2)
	rows, err := q.db.Query("SELECT id, email, password_hash, role, api_key, created_at, updated_at FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.APIKey, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (q *Queries) UpdateUserRole(userID, role string) error {
	// BUG-099: SQL injection via string concatenation for user ID (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
	query := fmt.Sprintf("UPDATE users SET role = '%s', updated_at = NOW() WHERE id = %s", role, userID)
	_, err := q.db.Exec(query)
	return err
}

// ---- Deployment Queries ----

func (q *Queries) GetDeployment(id int) (*models.Deployment, error) {
	d := &models.Deployment{}
	err := q.db.QueryRow(
		"SELECT id, name, namespace, image, replicas, status, owner_id, created_at, updated_at FROM deployments WHERE id = $1",
		id,
	).Scan(&d.ID, &d.Name, &d.Namespace, &d.Image, &d.Replicas, &d.Status, &d.Owner, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (q *Queries) CreateDeploymentRecord(name, namespace, image string, replicas int32, ownerID string) error {
	_, err := q.db.Exec(
		"INSERT INTO deployments (name, namespace, image, replicas, status, owner_id, created_at, updated_at) VALUES ($1, $2, $3, $4, 'active', $5, $6, $6)",
		name, namespace, image, replicas, ownerID, time.Now(),
	)
	return err
}

func (q *Queries) UpdateDeploymentRecord(id int, image string, replicas int32) error {
	_, err := q.db.Exec(
		"UPDATE deployments SET image = $1, replicas = $2, updated_at = $3 WHERE id = $4",
		image, replicas, time.Now(), id,
	)
	return err
}

func (q *Queries) DeleteDeploymentRecord(id int) error {
	_, err := q.db.Exec("DELETE FROM deployments WHERE id = $1", id)
	return err
}

// ---- Secret Queries ----

func (q *Queries) GetSecret(id int) (*models.Secret, error) {
	s := &models.Secret{}
	err := q.db.QueryRow(
		"SELECT id, name, namespace, value, type, owner_id, created_at FROM secrets WHERE id = $1",
		id,
	).Scan(&s.ID, &s.Name, &s.Namespace, &s.Value, &s.Type, &s.Owner, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (q *Queries) ListSecrets(namespace string) ([]models.Secret, error) {
	rows, err := q.db.Query(
		"SELECT id, name, namespace, value, type, owner_id, created_at FROM secrets WHERE namespace = $1 ORDER BY name",
		namespace,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secrets []models.Secret
	for rows.Next() {
		var s models.Secret
		if err := rows.Scan(&s.ID, &s.Name, &s.Namespace, &s.Value, &s.Type, &s.Owner, &s.CreatedAt); err != nil {
			return nil, err
		}
		secrets = append(secrets, s)
	}
	return secrets, nil
}

func (q *Queries) ListUserSecrets(namespace, userID string) ([]models.Secret, error) {
	rows, err := q.db.Query(
		"SELECT id, name, namespace, value, type, owner_id, created_at FROM secrets WHERE namespace = $1 AND owner_id = $2 ORDER BY name",
		namespace, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secrets []models.Secret
	for rows.Next() {
		var s models.Secret
		if err := rows.Scan(&s.ID, &s.Name, &s.Namespace, &s.Value, &s.Type, &s.Owner, &s.CreatedAt); err != nil {
			return nil, err
		}
		secrets = append(secrets, s)
	}
	return secrets, nil
}

func (q *Queries) CreateSecret(name, namespace, value, secretType, ownerID string) (*models.Secret, error) {
	s := &models.Secret{}
	err := q.db.QueryRow(
		"INSERT INTO secrets (name, namespace, value, type, owner_id, created_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, namespace, value, type, owner_id, created_at",
		name, namespace, value, secretType, ownerID, time.Now(),
	).Scan(&s.ID, &s.Name, &s.Namespace, &s.Value, &s.Type, &s.Owner, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (q *Queries) UpdateSecret(id int, value string) error {
	_, err := q.db.Exec("UPDATE secrets SET value = $1 WHERE id = $2", value, id)
	return err
}

func (q *Queries) DeleteSecret(id int) error {
	_, err := q.db.Exec("DELETE FROM secrets WHERE id = $1", id)
	return err
}

// ---- Audit Log Queries ----

func (q *Queries) CreateAuditLog(userID, action, resource, details string) {
	// BUG-100: Error from audit log insert not checked — silent audit log failure (CWE-252, CVSS 5.3, BEST_PRACTICE, Tier 5)
	q.db.Exec(
		"INSERT INTO audit_logs (user_id, action, resource, details, created_at) VALUES ($1, $2, $3, $4, $5)",
		userID, action, resource, details, time.Now(),
	)
}

// BUG-048 implementation: SQL injection in audit log filter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
func (q *Queries) GetAuditLogs(filter string) ([]models.AuditLog, error) {
	query := "SELECT id, user_id, action, resource, details, ip_address, created_at FROM audit_logs"
	if filter != "" {
		// String concatenation for SQL — classic injection point
		query += " WHERE action LIKE '%" + filter + "%' OR resource LIKE '%" + filter + "%' OR details LIKE '%" + filter + "%'"
	}
	query += " ORDER BY created_at DESC LIMIT 1000"

	log.Printf("Audit query: %s", query)

	rows, err := q.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		if err := rows.Scan(&l.ID, &l.UserID, &l.Action, &l.Resource, &l.Details, &l.IP, &l.Timestamp); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// ---- Bulk Operations ----

// RH-007: This looks like it uses string concatenation for SQL, but it actually
// uses parameterized placeholders ($1, $2...) built dynamically. The values
// are always passed as args, never interpolated into the query string.
func (q *Queries) BulkDeleteDeployments(ids []int) error {
	if len(ids) == 0 {
		return nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	query := fmt.Sprintf("DELETE FROM deployments WHERE id IN (%s)", strings.Join(placeholders, ","))
	_, err := q.db.Exec(query, args...)
	return err
}

func (q *Queries) SearchDeployments(term string) ([]models.Deployment, error) {
	rows, err := q.db.Query(
		"SELECT id, name, namespace, image, replicas, status, owner_id, created_at, updated_at FROM deployments WHERE name ILIKE $1 OR namespace ILIKE $1 ORDER BY name",
		"%"+term+"%",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deployments []models.Deployment
	for rows.Next() {
		var d models.Deployment
		if err := rows.Scan(&d.ID, &d.Name, &d.Namespace, &d.Image, &d.Replicas, &d.Status, &d.Owner, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		deployments = append(deployments, d)
	}
	return deployments, nil
}
