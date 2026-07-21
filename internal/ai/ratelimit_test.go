package ai

import (
	"errors"
	"testing"
)

func TestErrorTypes(t *testing.T) {
	var e error = &Error{Msg: "boom"}
	if e.Error() != "boom" {
		t.Errorf("Error() = %q", e.Error())
	}
	var re error = &RateLimitError{Msg: "slow down"}
	var target *RateLimitError
	if !errors.As(re, &target) {
		t.Error("RateLimitError non riconosciuto da errors.As")
	}
}

// Con rpm=2, la terza richiesta entro la finestra è rifiutata con un'attesa >0.
func TestRateLimiterBlocksOverRPM(t *testing.T) {
	rl := &rateLimiter{}
	rl.configure(2)
	if ok, _ := rl.allow(); !ok {
		t.Fatal("1a richiesta rifiutata")
	}
	if ok, _ := rl.allow(); !ok {
		t.Fatal("2a richiesta rifiutata")
	}
	ok, wait := rl.allow()
	if ok {
		t.Error("3a richiesta ammessa oltre il limite rpm=2")
	}
	if wait <= 0 {
		t.Errorf("attesa suggerita = %v, attesa >0", wait)
	}
}

// rpm<=0 = illimitato.
func TestRateLimiterUnlimited(t *testing.T) {
	rl := &rateLimiter{}
	rl.configure(0)
	for i := 0; i < 100; i++ {
		if ok, _ := rl.allow(); !ok {
			t.Fatalf("richiesta %d rifiutata con rpm illimitato", i)
		}
	}
}
