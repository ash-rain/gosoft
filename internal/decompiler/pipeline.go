package decompiler

import (
	"context"
	"fmt"

	"softy/internal/ai"
	binpkg "softy/internal/binary"
	ctxpkg "softy/internal/context"
	"softy/internal/disasm"
	"softy/internal/symbols"
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

// BuildFunctionContext builds the disassembly-level context for a function
// without calling the AI provider. This is useful for populating the
// disassembly view in the TUI independently of decompilation.
func BuildFunctionContext(b *binpkg.Binary, funcName string) (*ctxpkg.FunctionContext, error) {
	sym := symbols.FindSymbol(b, funcName)
	if sym == nil {
		return nil, fmt.Errorf("function %q not found in binary", funcName)
	}

	archStr := string(b.Arch)
	if b.Format == binpkg.FormatDotNet {
		archStr = "il"
	}
	d, err := disasm.New(archStr)
	if err != nil {
		return nil, fmt.Errorf("creating disassembler for arch %q: %w", archStr, err)
	}

	funcCtx, err := ctxpkg.Build(b, sym, d)
	if err != nil {
		return nil, fmt.Errorf("building function context for %q: %w", funcName, err)
	}
	return funcCtx, nil
}

// DecompileFunction decompiles a single named function from the binary.
func (p *Pipeline) DecompileFunction(goCtx context.Context, b *binpkg.Binary, funcName string, opts Options) (string, error) {
	funcCtx, err := BuildFunctionContext(b, funcName)
	if err != nil {
		return "", err
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
	funcCtx, err := BuildFunctionContext(b, funcName)
	if err != nil {
		return err
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
