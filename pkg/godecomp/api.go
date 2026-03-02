package godecomp

import (
	"context"
	"fmt"

	"godecomp/internal/ai"
	binpkg "godecomp/internal/binary"
	"godecomp/internal/decompiler"
	"godecomp/internal/symbols"
	"godecomp/internal/tui"
)

// Config holds configuration for the godecomp library.
type Config struct {
	OllamaURL      string
	OllamaModel    string
	OpenCodeURL    string
	OpenCodeAPIKey string
	OpenCodeModel  string
	DefaultLang    string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		OllamaURL:   "http://localhost:11434",
		OllamaModel: "deepseek-coder:latest",
		DefaultLang: "go",
	}
}

// Session holds a loaded binary and its associated pipeline.
type Session struct {
	Binary   *binpkg.Binary
	Pipeline *decompiler.Pipeline
	config   Config
}

// Open loads a binary file and creates a session.
func Open(path string, cfg Config) (*Session, error) {
	b, err := binpkg.Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading binary %q: %w", path, err)
	}

	// Set up AI providers
	var providers []ai.Provider

	ollamaURL := cfg.OllamaURL
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}
	ollamaModel := cfg.OllamaModel
	if ollamaModel == "" {
		ollamaModel = "deepseek-coder:latest"
	}
	providers = append(providers, ai.NewOllama(ollamaURL, ollamaModel))

	// Add OpenCode provider if configured
	if cfg.OpenCodeURL != "" && cfg.OpenCodeAPIKey != "" {
		providers = append(providers, ai.NewOpenCode(
			cfg.OpenCodeURL,
			cfg.OpenCodeAPIKey,
			cfg.OpenCodeModel,
		))
	}

	router := ai.NewRouter(providers...)
	pipeline := decompiler.New(router)

	return &Session{
		Binary:   b,
		Pipeline: pipeline,
		config:   cfg,
	}, nil
}

// Decompile decompiles a function to the target language.
func (s *Session) Decompile(ctx context.Context, funcName, targetLang string) (string, error) {
	if targetLang == "" {
		targetLang = s.config.DefaultLang
	}
	if targetLang == "" {
		targetLang = "go"
	}

	return s.Pipeline.DecompileFunction(ctx, s.Binary, funcName, decompiler.Options{
		TargetLang: targetLang,
	})
}

// DecompileStream decompiles and streams output to the channel.
func (s *Session) DecompileStream(ctx context.Context, funcName, targetLang string, out chan<- ai.StreamChunk) error {
	if targetLang == "" {
		targetLang = s.config.DefaultLang
	}
	if targetLang == "" {
		targetLang = "go"
	}

	return s.Pipeline.DecompileFunctionStream(ctx, s.Binary, funcName, decompiler.Options{
		TargetLang: targetLang,
		Stream:     true,
	}, out)
}

// StartTUI launches the interactive TUI.
func (s *Session) StartTUI() error {
	cfg := tui.TUIConfig{
		OllamaURL:      s.config.OllamaURL,
		OllamaModel:    s.config.OllamaModel,
		OpenCodeURL:    s.config.OpenCodeURL,
		OpenCodeAPIKey: s.config.OpenCodeAPIKey,
		OpenCodeModel:  s.config.OpenCodeModel,
	}
	return tui.Run(s.Binary, s.Pipeline, cfg)
}

// Symbols returns all function symbols.
func (s *Session) Symbols() []binpkg.Symbol {
	return symbols.FunctionList(s.Binary)
}

// Strings returns all embedded strings.
func (s *Session) Strings() []binpkg.StringRef {
	return symbols.ExtractStrings(s.Binary)
}
