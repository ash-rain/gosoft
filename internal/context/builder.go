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

	// Enhanced metadata for richer AI context.
	Format       string // binary format: ELF, PE, MachO, etc.
	Bits         int    // 32 or 64
	FuncAddress  uint64 // entry point address
	FuncSize     uint64 // size in bytes (0 if unknown)
	FuncType     string // symbol type: "func", "object", etc.
	SectionName  string // section the function resides in
	SectionFlags string // section flags (r/w/x)
	CallingConv  string // inferred calling convention hint

	// Cross-references: resolved call targets found in the disassembly.
	CallTargets []CallTarget

	// Binary-level stats for broader context.
	TotalFuncs   int
	TotalImports int
	TotalStrings int
}

// CallTarget is a resolved call/branch target found in the disassembly.
type CallTarget struct {
	Address uint64
	Name    string // resolved symbol or import name (empty if unresolved)
	Source  string // "symbol", "import", or "unknown"
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
		BinaryName:   b.Path,
		Arch:         string(b.Arch),
		OS:           b.OS,
		FuncName:     sym.Name,
		Imports:      b.Imports,
		Format:       string(b.Format),
		Bits:         b.Bits,
		FuncAddress:  sym.Address,
		FuncSize:     sym.Size,
		FuncType:     sym.Type,
		CallingConv:  inferCallingConv(b),
		TotalFuncs:   countFuncs(b),
		TotalImports: len(b.Imports),
		TotalStrings: len(b.Strings),
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
			ctx.SectionName = sec.Name
			ctx.SectionFlags = sec.Flags
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
				ctx.SectionName = sec.Name
				ctx.SectionFlags = sec.Flags
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

	// Extract cross-references: resolve call/branch targets to known names.
	ctx.CallTargets = extractCallTargets(ctx.Disassembly, b)

	return ctx, nil
}

// extractCallTargets scans disassembly for call/branch instructions and
// resolves operand addresses against symbols and imports.
func extractCallTargets(instrs []disasm.Instruction, b *binary.Binary) []CallTarget {
	symMap := make(map[uint64]string, len(b.Symbols))
	for _, s := range b.Symbols {
		if s.Name != "" {
			symMap[s.Address] = s.Name
		}
	}
	impMap := make(map[uint64]string, len(b.Imports))
	for _, imp := range b.Imports {
		if imp.Name != "" {
			impMap[imp.Address] = imp.Name
		}
	}

	seen := make(map[uint64]bool)
	var targets []CallTarget

	for _, inst := range instrs {
		mn := strings.ToLower(inst.Mnemonic)
		if !isCallMnemonic(mn) {
			continue
		}

		addr := parseAddress(inst.OpStr)
		if addr == 0 || seen[addr] {
			continue
		}
		seen[addr] = true

		ct := CallTarget{Address: addr, Source: "unknown"}
		if name, ok := symMap[addr]; ok {
			ct.Name = name
			ct.Source = "symbol"
		} else if name, ok := impMap[addr]; ok {
			ct.Name = name
			ct.Source = "import"
		}
		targets = append(targets, ct)
	}
	return targets
}

func isCallMnemonic(mn string) bool {
	switch mn {
	case "call", "callq", "bl", "blr", "blx",
		"callvirt", "newobj", "calli":
		return true
	}
	return false
}

func parseAddress(op string) uint64 {
	op = strings.TrimSpace(op)
	var addr uint64
	if strings.HasPrefix(op, "0x") || strings.HasPrefix(op, "0X") {
		fmt.Sscanf(op, "0x%x", &addr)
		return addr
	}
	n, _ := fmt.Sscanf(op, "%x", &addr)
	if n == 1 {
		return addr
	}
	return 0
}

func inferCallingConv(b *binary.Binary) string {
	if string(b.Format) == "DotNet" {
		return "CLR managed"
	}
	switch b.Arch {
	case binary.ArchX8664:
		if b.OS == "windows" {
			return "Microsoft x64 (rcx, rdx, r8, r9)"
		}
		return "System V AMD64 (rdi, rsi, rdx, rcx, r8, r9)"
	case binary.ArchX86:
		if b.OS == "windows" {
			return "cdecl/stdcall (stack-based)"
		}
		return "cdecl (stack-based)"
	case binary.ArchARM64:
		return "AAPCS64 (x0-x7)"
	case binary.ArchARM:
		return "AAPCS32 (r0-r3)"
	}
	return ""
}

func countFuncs(b *binary.Binary) int {
	n := 0
	for _, s := range b.Symbols {
		if s.Type == "func" {
			n++
		}
	}
	if n == 0 {
		n = len(b.Symbols)
	}
	return n
}

// FormatPrompt formats a FunctionContext into a detailed LLM prompt.
func FormatPrompt(ctx *FunctionContext, targetLang string) string {
	var sb strings.Builder

	// ── Function signature & identity ──────────────────────────────────
	sb.WriteString(fmt.Sprintf("=== Function: %s ===\n", ctx.FuncName))
	sb.WriteString(fmt.Sprintf("Address: 0x%x", ctx.FuncAddress))
	if ctx.FuncSize > 0 {
		sb.WriteString(fmt.Sprintf("  Size: %d bytes", ctx.FuncSize))
	}
	if ctx.FuncType != "" {
		sb.WriteString(fmt.Sprintf("  Type: %s", ctx.FuncType))
	}
	sb.WriteString("\n")

	// ── Binary metadata ────────────────────────────────────────────────
	sb.WriteString(fmt.Sprintf("Binary: %s\n", ctx.BinaryName))
	sb.WriteString(fmt.Sprintf("Format: %s  Arch: %s (%d-bit)  OS: %s\n",
		ctx.Format, ctx.Arch, ctx.Bits, ctx.OS))
	if ctx.CallingConv != "" {
		sb.WriteString(fmt.Sprintf("Calling convention: %s\n", ctx.CallingConv))
	}
	if ctx.SectionName != "" {
		sb.WriteString(fmt.Sprintf("Section: %s", ctx.SectionName))
		if ctx.SectionFlags != "" {
			sb.WriteString(fmt.Sprintf("  Flags: %s", ctx.SectionFlags))
		}
		sb.WriteString("\n")
	}
	sb.WriteString(fmt.Sprintf("Binary totals: %d functions, %d imports, %d strings\n",
		ctx.TotalFuncs, ctx.TotalImports, ctx.TotalStrings))

	// ── Cross-references (calls made from this function) ───────────────
	if len(ctx.CallTargets) > 0 {
		sb.WriteString("\nCall targets from this function:\n")
		for _, ct := range ctx.CallTargets {
			if ct.Name != "" {
				sb.WriteString(fmt.Sprintf("  0x%x → %s (%s)\n", ct.Address, ct.Name, ct.Source))
			} else {
				sb.WriteString(fmt.Sprintf("  0x%x (unresolved)\n", ct.Address))
			}
		}
	}

	// ── Nearby symbols (neighbours for context) ─────────────────────────
	if len(ctx.Symbols) > 0 {
		sb.WriteString("\nNearby symbols:\n")
		for _, sym := range ctx.Symbols {
			if sym.Name == "" {
				continue
			}
			sb.WriteString(fmt.Sprintf("  0x%x  %s", sym.Address, sym.Name))
			if sym.Type != "" {
				sb.WriteString(fmt.Sprintf(" [%s]", sym.Type))
			}
			if sym.Size > 0 {
				sb.WriteString(fmt.Sprintf(" (%d bytes)", sym.Size))
			}
			sb.WriteString("\n")
		}
	}

	// ── Strings referenced in the function ───────────────────────────────
	if len(ctx.Strings) > 0 {
		sb.WriteString("\nStrings referenced:\n")
		for _, s := range ctx.Strings {
			sb.WriteString(fmt.Sprintf("  0x%x  %q\n", s.Offset, s.Value))
		}
	}

	// ── Imports available in the binary ──────────────────────────────────
	if len(ctx.Imports) > 0 {
		sb.WriteString("\nImports:\n")
		seen := make(map[string]bool)
		for _, imp := range ctx.Imports {
			key := imp.Name
			if key == "" {
				continue
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			lib := ""
			if imp.Library != "" {
				lib = imp.Library + ":"
			}
			sb.WriteString(fmt.Sprintf("  0x%x  %s%s\n", imp.Address, lib, imp.Name))
		}
	}

	// ── Disassembly listing ──────────────────────────────────────────────
	sb.WriteString("\nDisassembly:\n")
	for _, inst := range ctx.Disassembly {
		line := fmt.Sprintf("  0x%08x  %-8s %s", inst.Address, inst.Mnemonic, inst.OpStr)
		if inst.Comment != "" {
			line += "  ; " + inst.Comment
		}
		sb.WriteString(line + "\n")
	}

	// ── Task ─────────────────────────────────────────────────────────────
	sb.WriteString(fmt.Sprintf("\nDecompile the above function to clean, idiomatic %s.\n", targetLang))
	sb.WriteString("Use the calling convention, imports, strings, and cross-references above to infer parameter names, types, and return values.\n")

	return sb.String()
}
