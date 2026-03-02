package context

import (
	"fmt"
	"strings"

	"godecomp/internal/binary"
	"godecomp/internal/disasm"
)

// FunctionContext holds all context needed for LLM decompilation.
type FunctionContext struct {
	BinaryName  string
	Arch        string
	OS          string
	FuncName    string
	Disassembly []disasm.Instruction
	Symbols     []binary.Symbol    // nearby symbols for context
	Strings     []binary.StringRef // strings referenced in the function range
	Imports     []binary.Import
}

// Build builds a FunctionContext for the given symbol in the binary.
// For .NET assemblies the IL disassembler is selected automatically.
func Build(b *binary.Binary, sym *binary.Symbol, d disasm.Disassembler) (*FunctionContext, error) {
	// Override disassembler for .NET binaries
	if b.Format == binary.FormatDotNet && (d == nil || d.Arch() != "il") {
		ilDis, err := disasm.New("il")
		if err == nil {
			d = ilDis
		}
	}
	if b == nil {
		return nil, fmt.Errorf("binary is nil")
	}
	if sym == nil {
		return nil, fmt.Errorf("symbol is nil")
	}
	if d == nil {
		return nil, fmt.Errorf("disassembler is nil")
	}

	ctx := &FunctionContext{
		BinaryName: b.Path,
		Arch:       string(b.Arch),
		OS:         b.OS,
		FuncName:   sym.Name,
		Imports:    b.Imports,
	}

	// Find the section containing this symbol.
	// For .NET assemblies, IL sections store Offset == sym.Address (the RVA).
	var funcData []byte
	var funcOffset uint64

	// First: try exact IL section match (for .NET)
	ilSectionName := "IL:" + sym.Name
	for _, sec := range b.Sections {
		if sec.Name == ilSectionName {
			funcData = sec.Data
			funcOffset = sec.Offset
			break
		}
	}

	// Fallback: scan sections by address range
	if len(funcData) == 0 {
		for _, sec := range b.Sections {
			secEnd := sec.Offset + sec.Size
			if sym.Address >= sec.Offset && sym.Address < secEnd {
				relOffset := sym.Address - sec.Offset
				if relOffset >= uint64(len(sec.Data)) {
					continue
				}

				var end uint64
				if sym.Size > 0 {
					end = relOffset + sym.Size
				} else {
					end = relOffset + 512
				}
				if end > uint64(len(sec.Data)) {
					end = uint64(len(sec.Data))
				}

				funcData = sec.Data[relOffset:end]
				funcOffset = sym.Address
				break
			}
		}
	}

	// If no section found, try to use raw data at offset
	if len(funcData) == 0 {
		// Fall through with empty disassembly - still provide context
	}

	// Disassemble the function data
	if len(funcData) > 0 {
		instructions, err := d.Disassemble(funcData, funcOffset)
		if err != nil {
			return nil, fmt.Errorf("disassembling function %q: %w", sym.Name, err)
		}
		ctx.Disassembly = instructions
	}

	// Collect nearby symbols (within 4KB range)
	const nearbyRange = 4096
	for _, s := range b.Symbols {
		diff := int64(s.Address) - int64(sym.Address)
		if diff < 0 {
			diff = -diff
		}
		if diff < nearbyRange && s.Name != sym.Name {
			ctx.Symbols = append(ctx.Symbols, s)
		}
	}

	// Collect strings referenced in the function address range
	if len(ctx.Disassembly) > 0 {
		funcStart := ctx.Disassembly[0].Address
		funcEnd := ctx.Disassembly[len(ctx.Disassembly)-1].Address + uint64(len(ctx.Disassembly[len(ctx.Disassembly)-1].Bytes))
		for _, s := range b.Strings {
			if s.Offset >= funcStart && s.Offset < funcEnd {
				ctx.Strings = append(ctx.Strings, s)
			}
		}
	}

	return ctx, nil
}

// FormatPrompt formats a FunctionContext into the LLM prompt text.
func FormatPrompt(ctx *FunctionContext, targetLang string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Function: %s\n", ctx.FuncName))
	sb.WriteString(fmt.Sprintf("Binary: %s (%s, %s)\n", ctx.BinaryName, ctx.Arch, ctx.OS))

	// Known symbols
	symbolNames := make([]string, 0, len(ctx.Symbols))
	for _, sym := range ctx.Symbols {
		if sym.Name != "" {
			symbolNames = append(symbolNames, sym.Name)
		}
	}
	sb.WriteString(fmt.Sprintf("Known symbols: %s\n", strings.Join(symbolNames, ", ")))

	// Strings referenced
	strVals := make([]string, 0, len(ctx.Strings))
	for _, s := range ctx.Strings {
		strVals = append(strVals, fmt.Sprintf("%q", s.Value))
	}
	sb.WriteString(fmt.Sprintf("Strings referenced: %s\n", strings.Join(strVals, ", ")))

	// Imports
	importNames := make([]string, 0, len(ctx.Imports))
	seen := make(map[string]bool)
	for _, imp := range ctx.Imports {
		key := imp.Name
		if key == "" {
			key = imp.Library
		}
		if key != "" && !seen[key] {
			seen[key] = true
			importNames = append(importNames, key)
		}
	}
	sb.WriteString(fmt.Sprintf("Imports: %s\n", strings.Join(importNames, ", ")))

	sb.WriteString("\nDisassembly:\n")
	for _, inst := range ctx.Disassembly {
		sb.WriteString(fmt.Sprintf("0x%08x  %s %s\n", inst.Address, inst.Mnemonic, inst.OpStr))
	}

	sb.WriteString(fmt.Sprintf("\nDecompile the above to idiomatic %s:\n", targetLang))

	return sb.String()
}
