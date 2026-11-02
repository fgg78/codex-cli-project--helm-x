package svc

import (
	"testing"

	"github.com/ADWMC/helm-x/internal/assets"
	"github.com/ADWMC/helm-x/internal/codexcfg"
)

func TestCustomPromptSaveAndFullModeBodies(t *testing.T) {
	s := newTestServices(t, codexcfg.Home{})
	body := "Custom instructions\nKeep every line."
	if err := s.Prompt.SaveCustom(body); err != nil {
		t.Fatal(err)
	}
	if got := s.rt.NewProxyConfig().PromptInstruction(); got != body {
		t.Fatalf("proxy prompt = %q, want saved custom body %q", got, body)
	}
	modes, err := s.Prompt.Modes()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range modes {
		if mode.ID == "custom" {
			if mode.Preview != body || !mode.Active {
				t.Fatalf("custom mode = %+v, want full body and active", mode)
			}
			continue
		}
		if mode.Preview != assets.Prompt(mode.ID) {
			t.Fatalf("mode %q returned incomplete prompt body", mode.ID)
		}
	}
}

func TestSaveCustomPromptRejectsEmptyBody(t *testing.T) {
	s := newTestServices(t, codexcfg.Home{})
	if err := s.Prompt.SaveCustom("\n \t"); err == nil {
		t.Fatal("whitespace-only custom prompt should be rejected")
	}
}
