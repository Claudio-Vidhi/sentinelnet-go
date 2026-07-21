package ai

import "testing"

func TestGetDefaultModel(t *testing.T) {
	if GetDefaultModel("anthropic") != "claude-sonnet-5" {
		t.Errorf("anthropic default = %q, atteso claude-sonnet-5 (divergenza §13)", GetDefaultModel("anthropic"))
	}
	if GetDefaultModel("openai") != "gpt-4o-mini" {
		t.Errorf("openai default = %q", GetDefaultModel("openai"))
	}
	if GetDefaultModel("GEMINI") != "gemini-3-flash" {
		t.Errorf("gemini default (case-insensitive) = %q", GetDefaultModel("GEMINI"))
	}
	if GetDefaultModel("bogus") != "" {
		t.Errorf("provider ignoto deve dare \"\", ottenuto %q", GetDefaultModel("bogus"))
	}
}

func TestNormalizeGeminiModel(t *testing.T) {
	if got := normalizeGeminiModel("models/models/gemini-3-flash"); got != "gemini-3-flash" {
		t.Errorf("normalize = %q", got)
	}
	if got := normalizeGeminiModel(""); got != "gemini-3-flash" {
		t.Errorf("normalize(\"\") deve dare il default gemini, ottenuto %q", got)
	}
}

func TestIsOpenAINonChat(t *testing.T) {
	for _, id := range []string{"text-embedding-3-small", "whisper-1", "dall-e-3", "gpt-4o-transcribe"} {
		if !isOpenAINonChat(id) {
			t.Errorf("%q dovrebbe essere non-chat", id)
		}
	}
	if isOpenAINonChat("gpt-4o") {
		t.Error("gpt-4o è chat, non deve essere filtrato")
	}
}
