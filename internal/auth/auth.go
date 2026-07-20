// Package auth: JWT HS256, hashing bcrypt, lockout tentativi e token OTP per la WS.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	TokenTTL        = 8 * time.Hour
	maxFailures     = 5
	lockoutDuration = 5 * time.Minute
	wsTokenTTL      = 30 * time.Second
)

type Service struct {
	secret []byte

	mu       sync.Mutex
	failures map[string]*failState
	wsTokens map[string]wsToken
}

type failState struct {
	count int
	until time.Time
}

type wsToken struct {
	username string
	expires  time.Time
}

// LoadJWTSecret: da env oppure file persistito (generato alla prima esecuzione).
func LoadJWTSecret(envSecret []byte, keyPath string) ([]byte, error) {
	if len(envSecret) > 0 {
		return envSecret, nil
	}
	if b, err := os.ReadFile(keyPath); err == nil && len(b) >= 32 {
		return b, nil
	}
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

func New(secret []byte) *Service {
	return &Service{
		secret:   secret,
		failures: map[string]*failState{},
		wsTokens: map[string]wsToken{},
	}
}

// MinPasswordLength allinea la policy a security/user_manager.py (MIN_PASSWORD_LENGTH = 8).
const MinPasswordLength = 8

// ValidatePassword è l'unico punto di verità della policy password: gli handler
// non devono reimplementare il controllo di lunghezza.
func ValidatePassword(plain string) error {
	if len(plain) < MinPasswordLength {
		return fmt.Errorf("la password deve contenere almeno %d caratteri", MinPasswordLength)
	}
	return nil
}

func HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(b), err
}

func CheckPassword(hashed, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain)) == nil
}

// ---- Lockout ----

var ErrLockedOut = errors.New("account temporaneamente bloccato per troppi tentativi")

func (s *Service) CheckLockout(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[username]
	if f != nil && f.count >= maxFailures && time.Now().Before(f.until) {
		return ErrLockedOut
	}
	return nil
}

func (s *Service) RecordFailure(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[username]
	if f == nil {
		f = &failState{}
		s.failures[username] = f
	}
	f.count++
	if f.count >= maxFailures {
		f.until = time.Now().Add(lockoutDuration)
	}
}

func (s *Service) ResetFailures(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, username)
}

// ---- JWT ----

type Claims struct {
	Username string
	Role     string
}

func (s *Service) IssueToken(username, role string) (string, error) {
	claims := jwt.MapClaims{
		"sub":  username,
		"role": role,
		"exp":  time.Now().Add(TokenTTL).Unix(),
		"iat":  time.Now().Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
}

func (s *Service) ParseToken(tokenStr string) (*Claims, error) {
	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("metodo di firma inatteso")
		}
		return s.secret, nil
	})
	if err != nil || !tok.Valid {
		return nil, errors.New("token non valido")
	}
	mc, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("claims non validi")
	}
	sub, _ := mc["sub"].(string)
	role, _ := mc["role"].(string)
	if sub == "" {
		return nil, errors.New("token senza subject")
	}
	return &Claims{Username: sub, Role: role}, nil
}

// ---- OTP monouso per il terminale WebSocket ----

func (s *Service) IssueWSToken(username string) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	// pulizia dei token scaduti
	now := time.Now()
	for k, v := range s.wsTokens {
		if now.After(v.expires) {
			delete(s.wsTokens, k)
		}
	}
	s.wsTokens[tok] = wsToken{username: username, expires: now.Add(wsTokenTTL)}
	return tok, nil
}

// ConsumeWSToken valida e brucia il token (monouso).
func (s *Service) ConsumeWSToken(tok string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.wsTokens[tok]
	if !ok || time.Now().After(v.expires) {
		return "", false
	}
	delete(s.wsTokens, tok)
	return v.username, true
}
