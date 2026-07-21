package ai

// Error è un errore di alto livello (config o rete verso il provider).
// Porta di AiAssistantError.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// RateLimitError: superato il limite richieste/minuto (locale o del provider).
// Porta di RateLimitExceededError.
type RateLimitError struct{ Msg string }

func (e *RateLimitError) Error() string { return e.Msg }
