package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type AIConversationSummary struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	CreatedTS int64  `json:"created_ts"`
	UpdatedTS int64  `json:"updated_ts"`
	Username  string `json:"username"`
}

type AIConversation struct {
	ID        int64          `json:"id"`
	Title     string         `json:"title"`
	Messages  []any          `json:"messages"`
	CreatedTS int64          `json:"created_ts"`
	UpdatedTS int64          `json:"updated_ts"`
	Username  string         `json:"username"`
}

func (s *Store) ListAIConversations(username string) ([]AIConversationSummary, error) {
	rows, err := s.DB.Query(
		`SELECT id, title, created_ts, updated_ts, username
		 FROM ai_conversations
		 WHERE username = ?
		 ORDER BY updated_ts DESC`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []AIConversationSummary
	for rows.Next() {
		var item AIConversationSummary
		if err := rows.Scan(&item.ID, &item.Title, &item.CreatedTS, &item.UpdatedTS, &item.Username); err == nil {
			list = append(list, item)
		}
	}
	return list, nil
}

func (s *Store) GetAIConversation(id int64, username string) (*AIConversation, error) {
	var c AIConversation
	var msgJSON string
	err := s.DB.QueryRow(
		`SELECT id, title, messages_json, created_ts, updated_ts, username
		 FROM ai_conversations
		 WHERE id = ? AND username = ?`, id, username).
		Scan(&c.ID, &c.Title, &msgJSON, &c.CreatedTS, &c.UpdatedTS, &c.Username)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(msgJSON), &c.Messages)
	return &c, nil
}

func (s *Store) CreateAIConversation(title string, messages any, username string) (*AIConversation, error) {
	now := time.Now().Unix()
	msgJSON, err := json.Marshal(messages)
	if err != nil {
		msgJSON = []byte("[]")
	}

	if title == "" {
		title = "Nuova conversazione"
	}

	res, err := s.DB.Exec(
		`INSERT INTO ai_conversations (title, messages_json, created_ts, updated_ts, username)
		 VALUES (?, ?, ?, ?, ?)`,
		title, string(msgJSON), now, now, username)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetAIConversation(id, username)
}

func (s *Store) UpdateAIConversation(id int64, title string, messages any, username string) (*AIConversation, error) {
	now := time.Now().Unix()
	existing, err := s.GetAIConversation(id, username)
	if err != nil || existing == nil {
		return nil, fmt.Errorf("conversazione non trovata")
	}

	if title == "" {
		title = existing.Title
	}

	var msgJSON []byte
	if messages != nil {
		msgJSON, _ = json.Marshal(messages)
	} else {
		msgJSON, _ = json.Marshal(existing.Messages)
	}

	_, err = s.DB.Exec(
		`UPDATE ai_conversations
		 SET title = ?, messages_json = ?, updated_ts = ?
		 WHERE id = ? AND username = ?`,
		title, string(msgJSON), now, id, username)
	if err != nil {
		return nil, err
	}

	return s.GetAIConversation(id, username)
}

func (s *Store) DeleteAIConversation(id int64, username string) error {
	_, err := s.DB.Exec(`DELETE FROM ai_conversations WHERE id = ? AND username = ?`, id, username)
	return err
}

// SNMP Tenant Defaults
func (s *Store) GetSNMPTenantDefaults() ([]string, error) {
	rows, err := s.DB.Query(`SELECT tenant FROM snmp_tenant_defaults WHERE community != '' ORDER BY tenant`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tenants []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err == nil {
			tenants = append(tenants, t)
		}
	}
	return tenants, nil
}

func (s *Store) SetSNMPTenantDefault(tenant, community string) error {
	if community == "" {
		_, err := s.DB.Exec(`DELETE FROM snmp_tenant_defaults WHERE tenant = ?`, tenant)
		return err
	}
	_, err := s.DB.Exec(
		`INSERT INTO snmp_tenant_defaults (tenant, community)
		 VALUES (?, ?)
		 ON CONFLICT(tenant) DO UPDATE SET community = excluded.community`,
		tenant, community)
	return err
}
