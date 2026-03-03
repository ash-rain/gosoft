package decompiler

import (
	"strings"
	"testing"

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
			{Address: 0x1006, Bytes: []byte{0xc3}, Mnemonic: "ret", OpStr: ""},
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
			// Should have pseudo-translated push, mov, xor, ret.
			if !strings.Contains(result, "stack_push") {
				t.Errorf("expected 'stack_push' for push instruction in %s", lang)
			}
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
