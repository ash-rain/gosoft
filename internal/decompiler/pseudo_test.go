package decompiler

import (
	"strings"
	"testing"

	"godecomp/internal/binary"
	ctxpkg "godecomp/internal/context"
	"godecomp/internal/disasm"
)

func TestQuickDecompile_AllLanguages(t *testing.T) {
	ctx := &ctxpkg.FunctionContext{
		BinaryName: "test.exe",
		Arch:       "x86_64",
		OS:         "linux",
		FuncName:   "main",
		Disassembly: []disasm.Instruction{
			{Address: 0x1000, Bytes: []byte{0x55}, Mnemonic: "push", OpStr: "rbp"},
			{Address: 0x1001, Bytes: []byte{0x48, 0x89, 0xe5}, Mnemonic: "mov", OpStr: "rbp, rsp"},
			{Address: 0x1004, Bytes: []byte{0x31, 0xc0}, Mnemonic: "xor", OpStr: "eax, eax"},
			{Address: 0x1006, Bytes: []byte{0x5d}, Mnemonic: "pop", OpStr: "rbp"},
			{Address: 0x1007, Bytes: []byte{0xc3}, Mnemonic: "ret", OpStr: ""},
		},
	}

	for _, lang := range SupportedLanguages() {
		t.Run(lang, func(t *testing.T) {
			result := QuickDecompile(ctx, lang)
			if result == "" {
				t.Fatal("expected non-empty output")
			}
			// All languages should contain the function name.
			if !strings.Contains(result, "main") {
				t.Errorf("expected output to contain function name 'main', got:\n%s", result)
			}
			// Prologue (push rbp, mov rbp,rsp) should be suppressed.
			if strings.Contains(result, "save rbp") || strings.Contains(result, "stack_push") {
				t.Errorf("expected prologue instructions to be suppressed in %s, got:\n%s", lang, result)
			}
			// Should have return.
			if !strings.Contains(result, "return") {
				t.Errorf("expected 'return' for ret instruction in %s", lang)
			}
			// xor eax, eax should produce eax = 0.
			if !strings.Contains(result, "eax") || !strings.Contains(result, "0") {
				t.Errorf("expected xor eax,eax -> eax = 0 in %s", lang)
			}
		})
	}
}

func TestQuickDecompile_ControlFlow(t *testing.T) {
	// Test: cmp + conditional jump → merged if statement with labels.
	ctx := &ctxpkg.FunctionContext{
		BinaryName: "test.exe",
		Arch:       "x86_64",
		OS:         "linux",
		FuncName:   "check_value",
		Disassembly: []disasm.Instruction{
			{Address: 0x1000, Bytes: []byte{0x83, 0xf8, 0x0a}, Mnemonic: "cmp", OpStr: "eax, 0xa"},
			{Address: 0x1003, Bytes: []byte{0x75, 0x05}, Mnemonic: "jne", OpStr: "0x100a"},
			{Address: 0x1005, Bytes: []byte{0x31, 0xc0}, Mnemonic: "xor", OpStr: "eax, eax"},
			{Address: 0x1007, Bytes: []byte{0xc3}, Mnemonic: "ret", OpStr: ""},
			{Address: 0x100a, Bytes: []byte{0xb8, 0x01, 0x00, 0x00, 0x00}, Mnemonic: "mov", OpStr: "eax, 0x1"},
			{Address: 0x100f, Bytes: []byte{0xc3}, Mnemonic: "ret", OpStr: ""},
		},
	}

	result := QuickDecompile(ctx, "c")

	// Should have a merged if statement instead of separate cmp + jne.
	if !strings.Contains(result, "if (") {
		t.Errorf("expected merged cmp+jne → if statement, got:\n%s", result)
	}
	// Should have a label for the jump target.
	if !strings.Contains(result, "L0") {
		t.Errorf("expected label L0 for jump target 0x100a, got:\n%s", result)
	}
}

func TestQuickDecompile_SymbolResolution(t *testing.T) {
	ctx := &ctxpkg.FunctionContext{
		BinaryName: "test.exe",
		Arch:       "x86_64",
		OS:         "linux",
		FuncName:   "caller",
		Disassembly: []disasm.Instruction{
			{Address: 0x2000, Bytes: []byte{0xe8}, Mnemonic: "call", OpStr: "0x3000"},
			{Address: 0x2005, Bytes: []byte{0xc3}, Mnemonic: "ret", OpStr: ""},
		},
		Symbols: []binary.Symbol{
			{Name: "helper_func", Address: 0x3000, Size: 32, Type: "func"},
		},
	}

	result := QuickDecompile(ctx, "go")

	// Should resolve call target 0x3000 → helper_func.
	if !strings.Contains(result, "helper_func()") {
		t.Errorf("expected resolved symbol 'helper_func()', got:\n%s", result)
	}
}

func TestQuickDecompile_ImportResolution(t *testing.T) {
	ctx := &ctxpkg.FunctionContext{
		BinaryName: "test.exe",
		Arch:       "x86_64",
		OS:         "windows",
		FuncName:   "main",
		Disassembly: []disasm.Instruction{
			{Address: 0x1000, Bytes: []byte{0xe8}, Mnemonic: "call", OpStr: "0x4000"},
			{Address: 0x1005, Bytes: []byte{0xc3}, Mnemonic: "ret", OpStr: ""},
		},
		Imports: []binary.Import{
			{Library: "kernel32.dll", Name: "ExitProcess", Address: 0x4000},
		},
	}

	result := QuickDecompile(ctx, "c")

	// Should resolve import.
	if !strings.Contains(result, "ExitProcess()") {
		t.Errorf("expected resolved import 'ExitProcess()', got:\n%s", result)
	}
	// Should list imports in header.
	if !strings.Contains(result, "kernel32.dll") {
		t.Errorf("expected import listing with library name, got:\n%s", result)
	}
}

func TestQuickDecompile_LoopDetection(t *testing.T) {
	ctx := &ctxpkg.FunctionContext{
		BinaryName: "test.exe",
		Arch:       "x86_64",
		OS:         "linux",
		FuncName:   "loop_func",
		Disassembly: []disasm.Instruction{
			{Address: 0x1000, Bytes: []byte{0x31, 0xc9}, Mnemonic: "xor", OpStr: "ecx, ecx"},
			// Loop header target:
			{Address: 0x1002, Bytes: []byte{0xff, 0xc1}, Mnemonic: "inc", OpStr: "ecx"},
			{Address: 0x1004, Bytes: []byte{0x83, 0xf9, 0x0a}, Mnemonic: "cmp", OpStr: "ecx, 0xa"},
			{Address: 0x1007, Bytes: []byte{0x7c, 0xf9}, Mnemonic: "jl", OpStr: "0x1002"},
			{Address: 0x1009, Bytes: []byte{0xc3}, Mnemonic: "ret", OpStr: ""},
		},
	}

	result := QuickDecompile(ctx, "c")

	// Should detect back-edge and mark as loop.
	if !strings.Contains(result, "loop") {
		t.Errorf("expected loop detection comment, got:\n%s", result)
	}
}

func TestQuickDecompile_IL(t *testing.T) {
	ctx := &ctxpkg.FunctionContext{
		BinaryName: "test.dll",
		Arch:       "il",
		OS:         "windows",
		FuncName:   "MyNamespace.MyClass::Hello",
		Disassembly: []disasm.Instruction{
			{Address: 0x00, Bytes: []byte{0x00}, Mnemonic: "nop", OpStr: ""},
			{Address: 0x01, Bytes: []byte{0x72}, Mnemonic: "ldstr", OpStr: "\"Hello\""},
			{Address: 0x06, Bytes: []byte{0x28}, Mnemonic: "call", OpStr: "System.Console::WriteLine"},
			{Address: 0x0B, Bytes: []byte{0x2A}, Mnemonic: "ret", OpStr: ""},
		},
	}

	for _, lang := range SupportedLanguages() {
		t.Run(lang, func(t *testing.T) {
			result := QuickDecompile(ctx, lang)
			if result == "" {
				t.Fatal("expected non-empty output")
			}
			if !strings.Contains(result, "Hello") {
				t.Errorf("expected output to contain 'Hello' from ldstr")
			}
			if !strings.Contains(result, "WriteLine") {
				t.Errorf("expected output to contain 'WriteLine' from call")
			}
		})
	}
}

func TestQuickDecompile_Empty(t *testing.T) {
	ctx := &ctxpkg.FunctionContext{
		FuncName: "empty_func",
	}
	result := QuickDecompile(ctx, "go")
	if !strings.Contains(result, "No disassembly") {
		t.Errorf("expected 'No disassembly' message for empty function, got:\n%s", result)
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"main", "main"},
		{"Namespace.Class::Method", "Namespace_Class_Method"},
		{"<Module>", "Module"},
		{"123start", "_123start"},
	}
	for _, tc := range tests {
		got := sanitizeName(tc.input)
		if got != tc.expected {
			t.Errorf("sanitizeName(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestQuickDecompile_NopSuppression(t *testing.T) {
	ctx := &ctxpkg.FunctionContext{
		BinaryName: "test.exe",
		Arch:       "x86_64",
		OS:         "linux",
		FuncName:   "aligned_func",
		Disassembly: []disasm.Instruction{
			{Address: 0x1000, Bytes: []byte{0x0f, 0x1f, 0x00}, Mnemonic: "nop", OpStr: ""},
			{Address: 0x1003, Bytes: []byte{0xf3, 0x0f, 0x1e, 0xfa}, Mnemonic: "endbr64", OpStr: ""},
			{Address: 0x1007, Bytes: []byte{0xb8, 0x01}, Mnemonic: "mov", OpStr: "eax, 0x1"},
			{Address: 0x100c, Bytes: []byte{0xc3}, Mnemonic: "ret", OpStr: ""},
		},
	}

	result := QuickDecompile(ctx, "c")

	// nop and endbr64 should be silently suppressed (not emitted as code).
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comments and function signature.
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "void") || strings.HasPrefix(trimmed, "func") ||
			strings.HasPrefix(trimmed, "fn") || strings.HasPrefix(trimmed, "def") ||
			strings.HasPrefix(trimmed, "function") || strings.HasPrefix(trimmed, "public") {
			continue
		}
		if strings.Contains(strings.ToLower(trimmed), "nop") {
			t.Errorf("nop should be suppressed, found: %s", line)
		}
	}
}
