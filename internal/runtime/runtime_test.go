package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ADWMC/helm-x/internal/logging"
	"github.com/ADWMC/helm-x/internal/proxy"
)

func TestCyberPolicyRequestWritesCyberLog(t *testing.T) {
	dir := t.TempDir()
	logger := logging.New(dir)
	t.Cleanup(func() { _ = logger.Close() })
	sink := &LoggerSink{Logger: logger, CyberDir: dir}
	sink.Request(proxy.RequestRecord{
		Path: "/v1/responses", Class: proxy.ClassCyberPolicy,
		Action: proxy.ActionPassThrough, Note: "流式网络安全策略拦截",
	})
	data, err := os.ReadFile(filepath.Join(dir, "helmx-cyber.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "CyberPolicy") || !strings.Contains(string(data), "/v1/responses") {
		t.Fatalf("cyber 日志缺少状态或路径: %s", data)
	}
}
