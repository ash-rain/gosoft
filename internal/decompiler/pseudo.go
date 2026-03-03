package decompiler

import (
	"fmt"
	"strings"

	ctxpkg "softy/internal/context"
)

// QuickDecompile generates pseudo-code from disassembly without an AI provider.
// It runs multi-pass analysis (basic blocks, label generation, prologue/epilogue
// detection, cmp+jump merging) to produce readable pseudo-code in the given
// target language.
func QuickDecompile(funcCtx *ctxpkg.FunctionContext, lang string) string {
	if funcCtx == nil || len(funcCtx.Disassembly) == 0 {
		return fmt.Sprintf("// No disassembly available for %s\n", funcCtx.FuncName)
	}

	a := newAnalysisCtx(funcCtx, lang)

	// ── Analysis passes ───────────────────────────────────────────────
	a.buildBlocks()
	a.generateLabels()
	a.detectPrologueEpilogue()

	// ── Emit output ───────────────────────────────────────────────────
	var sb strings.Builder

	// Header / function signature.
	sb.WriteString(pseudoSignature(funcCtx, lang))

	// Referenced strings as named constants.
	sb.WriteString(pseudoLocals(funcCtx, lang))

	// Emit imports/symbols summary if available.
	sb.WriteString(pseudoImports(funcCtx, lang))

	// Body: emit basic blocks with structure.
	for _, blk := range a.blocks {
		emitBlock(a, blk, &sb, 1)
	}

	// Footer.
	sb.WriteString(pseudoFooter(lang))

	return sb.String()
}

// ── Signature ─────────────────────────────────────────────────────────────

func pseudoSignature(ctx *ctxpkg.FunctionContext, lang string) string {
	name := sanitizeName(ctx.FuncName)
	comment := fmt.Sprintf("Quick offline decompilation of %s (%s/%s)", ctx.FuncName, ctx.Arch, ctx.OS)

	switch lang {
	case "c":
		return fmt.Sprintf("// %s\nvoid %s(void) {\n", comment, name)
	case "go":
		return fmt.Sprintf("// %s\nfunc %s() {\n", comment, name)
	case "rust":
		return fmt.Sprintf("// %s\nfn %s() {{\n", comment, name)
	case "python":
		return fmt.Sprintf("# %s\ndef %s():\n", comment, name)
	case "typescript":
		return fmt.Sprintf("// %s\nfunction %s(): void {\n", comment, name)
	case "java":
		return fmt.Sprintf("// %s\npublic static void %s() {\n", comment, name)
	case "csharp":
		return fmt.Sprintf("// %s\npublic static void %s() {\n", comment, name)
	default:
		return fmt.Sprintf("// %s\nfunction %s() {\n", comment, name)
	}
}

func pseudoLocals(ctx *ctxpkg.FunctionContext, lang string) string {
	var sb strings.Builder

	// Referenced strings as named constants.
	if len(ctx.Strings) > 0 {
		indent := "    "
		for i, s := range ctx.Strings {
			switch lang {
			case "c":
				sb.WriteString(fmt.Sprintf("%sconst char *str_%d = %q;\n", indent, i, s.Value))
			case "go":
				sb.WriteString(fmt.Sprintf("%sstr_%d := %q\n", indent, i, s.Value))
			case "rust":
				sb.WriteString(fmt.Sprintf("%slet str_%d: &str = %q;\n", indent, i, s.Value))
			case "python":
				sb.WriteString(fmt.Sprintf("%sstr_%d = %q\n", indent, i, s.Value))
			case "typescript":
				sb.WriteString(fmt.Sprintf("%sconst str_%d: string = %q;\n", indent, i, s.Value))
			case "java":
				sb.WriteString(fmt.Sprintf("%sString str_%d = %q;\n", indent, i, s.Value))
			case "csharp":
				sb.WriteString(fmt.Sprintf("%sstring str_%d = %q;\n", indent, i, s.Value))
			default:
				sb.WriteString(fmt.Sprintf("%svar str_%d = %q;\n", indent, i, s.Value))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func pseudoImports(ctx *ctxpkg.FunctionContext, lang string) string {
	if len(ctx.Imports) == 0 {
		return ""
	}
	var sb strings.Builder
	indent := "    "
	comment := commentPrefix(lang)
	sb.WriteString(fmt.Sprintf("%s%s Referenced imports:\n", indent, comment))
	for _, imp := range ctx.Imports {
		lib := ""
		if imp.Library != "" {
			lib = imp.Library + ":"
		}
		sb.WriteString(fmt.Sprintf("%s%s   %s%s @ 0x%x\n", indent, comment, lib, imp.Name, imp.Address))
	}
	sb.WriteString("\n")
	return sb.String()
}

// ── Footer ────────────────────────────────────────────────────────────────

func pseudoFooter(lang string) string {
	switch lang {
	case "python":
		return ""
	default:
		return "}\n"
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────

func commentPrefix(lang string) string {
	if lang == "python" {
		return "#"
	}
	return "//"
}

func splitOperands(op string) []string {
	parts := strings.SplitN(op, ",", 2)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func sanitizeName(name string) string {
	// Replace characters that are invalid in most identifiers.
	r := strings.NewReplacer(
		"::", "_",
		".", "_",
		"-", "_",
		"<", "",
		">", "",
		"/", "_",
		" ", "_",
		"(", "",
		")", "",
		",", "_",
		"*", "ptr",
	)
	s := r.Replace(name)
	if s == "" {
		return "unknown"
	}
	// Don't start with a digit.
	if s[0] >= '0' && s[0] <= '9' {
		s = "_" + s
	}
	return s
}

func sanitizeOp(op string) string {
	op = strings.TrimSpace(op)
	// Remove brackets from memory operands for readability.
	op = strings.TrimPrefix(op, "[")
	op = strings.TrimSuffix(op, "]")
	return op
}
