package decompiler

import (
	"context"
	"fmt"

	"godecomp/internal/ai"
	binpkg "godecomp/internal/binary"
	ctxpkg "godecomp/internal/context"
	"godecomp/internal/disasm"
	"godecomp/internal/symbols"
)

// Options configures the decompilation pipeline.
type Options struct {
	TargetLang string // "go", "c", "rust", etc.
	Model      string
	Stream     bool
}

// Pipeline orchestrates the decompilation process.
type Pipeline struct {
	provider ai.Provider
}

// New creates a new Pipeline with the given AI provider.
func New(provider ai.Provider) *Pipeline {
	return &Pipeline{provider: provider}
}

// DecompileFunction decompiles a single named function from the binary.
func (p *Pipeline) DecompileFunction(goCtx context.Context, b *binpkg.Binary, funcName string, opts Options) (string, error) {
	// Find the function symbol
	sym := symbols.FindSymbol(b, funcName)
	if sym == nil {
		return "", fmt.Errorf("function %q not found in binary", funcName)
	}

	// Use IL disassembler for .NET assemblies, native arch otherwise
	archStr := string(b.Arch)
	if b.Format == binpkg.FormatDotNet {
		archStr = "il"
	}
	d, err := disasm.New(archStr)
	if err != nil {
		return "", fmt.Errorf("creating disassembler for arch %q: %w", archStr, err)
	}

	// Build function context
	funcCtx, err := ctxpkg.Build(b, sym, d)
	if err != nil {
		return "", fmt.Errorf("building function context for %q: %w", funcName, err)
	}

	// Build prompts
	lang := opts.TargetLang
	if lang == "" {
		lang = "go"
	}

	userPrompt := ctxpkg.FormatPrompt(funcCtx, lang)
	sysPrompt := SystemPrompt(lang)

	// Call the AI provider
	result, err := p.provider.Complete(goCtx, ai.CompletionRequest{
		SystemPrompt: sysPrompt,
		UserPrompt:   userPrompt,
		Model:        opts.Model,
	})
	if err != nil {
		return "", fmt.Errorf("AI completion for %q: %w", funcName, err)
	}

	return result, nil
}

// DecompileFunctionStream decompiles and streams tokens to the out channel.
func (p *Pipeline) DecompileFunctionStream(goCtx context.Context, b *binpkg.Binary, funcName string, opts Options, out chan<- ai.StreamChunk) error {
	// Find the function symbol
	sym := symbols.FindSymbol(b, funcName)
	if sym == nil {
		return fmt.Errorf("function %q not found in binary", funcName)
	}

	archStr := string(b.Arch)
	if b.Format == binpkg.FormatDotNet {
		archStr = "il"
	}
	d, err := disasm.New(archStr)
	if err != nil {
		return fmt.Errorf("creating disassembler for arch %q: %w", archStr, err)
	}

	// Build function context
	funcCtx, err := ctxpkg.Build(b, sym, d)
	if err != nil {
		return fmt.Errorf("building function context for %q: %w", funcName, err)
	}

	// Build prompts
	lang := opts.TargetLang
	if lang == "" {
		lang = "go"
	}

	userPrompt := ctxpkg.FormatPrompt(funcCtx, lang)
	sysPrompt := SystemPrompt(lang)

	// Call the AI provider in streaming mode
	return p.provider.Stream(goCtx, ai.CompletionRequest{
		SystemPrompt: sysPrompt,
		UserPrompt:   userPrompt,
		Model:        opts.Model,
		Stream:       true,
	}, out)
}

// AskStream streams an open-ended question about the binary to the out channel.
func (p *Pipeline) AskStream(goCtx context.Context, systemPrompt, userPrompt string, out chan<- ai.StreamChunk) error {
	return p.provider.Stream(goCtx, ai.CompletionRequest{
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
		Stream:       true,
	}, out)
}
