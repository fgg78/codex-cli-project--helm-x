package rewriter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRewriteTrimsConfiguredModelAndRequiresChange(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("请求路径=%s", r.URL.Path)
		}
		var payload struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("解析请求: %v", err)
		}
		if payload.Model != "test-model" {
			t.Errorf("model=%q", payload.Model)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"原始请求"}}]}`))
	}))
	defer srv.Close()

	rw := New(Config{Enabled: true, BaseURL: srv.URL + "/v1", Model: " test-model ", MaxAttempts: 1}, "rewrite")
	if out, ok := rw.Rewrite(context.Background(), "原始请求", "", ""); ok || out != "" {
		t.Fatalf("相同文本不应作为改写结果: %q %t", out, ok)
	}
	if calls != 1 {
		t.Fatalf("API 调用数=%d, want 1", calls)
	}
}
