package decompiler

import (
	"context"
	"testing"

	"softy/internal/ai"
	"softy/internal/binary"
)

// mockProvider is a mock AI provider for testing.
type mockProvider struct{ response string }

func (m *mockProvider) Name() string { return "mock" }
func (m *mockProvider) Available(_ context.Context) bool { return true }
func (m *mockProvider) Complete(_ context.Context, _ ai.CompletionRequest) (string, error) {
	return m.response, nil
}
func (m *mockProvider) Stream(_ context.Context, req ai.CompletionRequest, out chan<- ai.StreamChunk) error {
	out <- ai.StreamChunk{Text: m.response, Done: false}
	out <- ai.StreamChunk{Done: true}
	close(out)
	return nil
}

// makeMockBinaryWithTextSection creates a mock binary with a text section containing
// actual decodable x86-64 instructions.
func makeMockBinaryWithTextSection() *binary.Binary {
	// NOP, MOV RAX RAX, RET bytes
	instrBytes := []byte{0x90, 0x48, 0x89, 0xc0, 0xc3}

	return &binary.Binary{
		Path:   "/tmp/test-binary",
		Format: binary.FormatELF,
		Arch:   binary.ArchX8664,
		Bits:   64,
		OS:     "linux",
		Sections: []binary.Section{
			{
				Name:   ".text",
				Offset: 0x1000,
				Size:   uint64(len(instrBytes)),
				Data:   instrBytes,
				Flags:  "AX",
			},
		},
		Symbols: []binary.Symbol{
			{
				Name:    "testFunc",
				Address: 0x1000,
				Size:    uint64(len(instrBytes)),
				Type:    "func",
			},
		},
		Imports: []binary.Import{
			{Library: "libc.so.6", Name: "printf"},
		},
		Strings: []binary.StringRef{
			{Value: "Hello", Offset: 0x2000, Section: ".rodata"},
		},
	}
}

func TestPipelineDecompileFunction(t *testing.T) {
	expectedOutput := "func testFunc() { // NOP; return }"

	mock := &mockProvider{response: expectedOutput}
	pipeline := New(mock)

	b := makeMockBinaryWithTextSection()
	ctx := context.Background()

	result, err := pipeline.DecompileFunction(ctx, b, "testFunc", Options{
		TargetLang: "go",
	})

	if err != nil {
		t.Fatalf("DecompileFunction() returned error: %v", err)
	}

	if result != expectedOutput {
		t.Errorf("expected %q, got %q", expectedOutput, result)
	}
}

func TestPipelineDecompileFunctionNotFound(t *testing.T) {
	mock := &mockProvider{response: ""}
	pipeline := New(mock)

	b := makeMockBinaryWithTextSection()
	ctx := context.Background()

	_, err := pipeline.DecompileFunction(ctx, b, "nonexistent_function", Options{
		TargetLang: "go",
	})

	if err == nil {
		t.Error("expected error for nonexistent function, got nil")
	}
}

func TestPipelineDecompileFunctionStream(t *testing.T) {
	expectedOutput := "func testFunc() { return nil }"

	mock := &mockProvider{response: expectedOutput}
	pipeline := New(mock)

	b := makeMockBinaryWithTextSection()
	ctx := context.Background()

	out := make(chan ai.StreamChunk, 100)
	err := pipeline.DecompileFunctionStream(ctx, b, "testFunc", Options{
		TargetLang: "go",
		Stream:     true,
	}, out)

	if err != nil {
		t.Fatalf("DecompileFunctionStream() returned error: %v", err)
	}

	var received string
	for chunk := range out {
		if chunk.Error != nil {
			t.Fatalf("stream chunk error: %v", chunk.Error)
		}
		if chunk.Done {
			break
		}
		received += chunk.Text
	}

	if received != expectedOutput {
		t.Errorf("expected %q, got %q", expectedOutput, received)
	}
}

func TestPipelineDefaultLang(t *testing.T) {
	expectedOutput := "// some code"
	mock := &mockProvider{response: expectedOutput}
	pipeline := New(mock)

	b := makeMockBinaryWithTextSection()
	ctx := context.Background()

	// Empty TargetLang should default to "go"
	result, err := pipeline.DecompileFunction(ctx, b, "testFunc", Options{})
	if err != nil {
		t.Fatalf("DecompileFunction() returned error: %v", err)
	}
	if result != expectedOutput {
		t.Errorf("expected %q, got %q", expectedOutput, result)
	}
}

func TestSystemPromptLanguages(t *testing.T) {
	for _, lang := range SupportedLanguages() {
		prompt := SystemPrompt(lang)
		if prompt == "" {
			t.Errorf("expected non-empty system prompt for lang %q", lang)
		}
	}
}
