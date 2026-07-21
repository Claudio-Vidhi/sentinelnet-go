package ai

import "testing"

func TestIsLocalBaseURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://localhost:11434", true},
		{"http://127.0.0.1:8080", true},
		{"http://10.0.0.5/v1", true},
		{"http://192.168.1.10:1234/v1", true},
		{"http://172.16.5.5", true},
		{"https://api.openai.com/v1", false},
		{"https://8.8.8.8", false},
		{"", false},
		{"not a url", false},
	}
	for _, c := range cases {
		if got := IsLocalBaseURL(c.url); got != c.want {
			t.Errorf("IsLocalBaseURL(%q) = %v, atteso %v", c.url, got, c.want)
		}
	}
}
