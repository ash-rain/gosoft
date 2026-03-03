package decompiler

import (
	"fmt"
	"strings"

	"softy/internal/disasm"
)

// ── Language helpers ──────────────────────────────────────────────────────

func langSemicolon(lang string) string {
	if lang == "python" || lang == "go" {
		return ""
	}
	return ";"
}

func langAssign(lang string) string {
	if lang == "go" {
		return " := "
	}
	return " = "
}

func labelIndent(lang, pad string) string {
	// Labels in Go must be at function-level indentation or less.
	if lang == "go" || lang == "python" {
		return ""
	}
	return pad
}

// ── Register / variable name helpers ──────────────────────────────────────

// regOrVar maps raw register names into slightly friendlier names.
func regOrVar(s string) string {
	s = strings.TrimSpace(s)
	// Memory operands kept as-is.
	if strings.HasPrefix(s, "[") || strings.HasPrefix(s, "qword") ||
		strings.HasPrefix(s, "dword") || strings.HasPrefix(s, "byte") ||
		strings.HasPrefix(s, "word") {
		return s
	}
	return s
}

// ── Branch / jump classification ──────────────────────────────────────────

// isJump returns true for any x86 j* instruction.
func isJump(mn string) bool {
	return strings.HasPrefix(mn, "j")
}

// isUnconditionalJump returns true for jmp.
func isUnconditionalJump(mn string) bool {
	return mn == "jmp" || mn == "jmpq"
}

// isConditionalJump returns true for x86 conditional jumps (je, jne, jg, ...).
func isConditionalJump(mn string) bool {
	if !strings.HasPrefix(mn, "j") {
		return false
	}
	return mn != "jmp" && mn != "jmpq"
}

// isBranch returns true for IL and ARM branch mnemonics.
func isBranch(mn string) bool {
	switch mn {
	case "br", "br.s", "brfalse", "brfalse.s", "brtrue", "brtrue.s",
		"brnull", "brnull.s", "brinst", "brinst.s",
		"beq", "beq.s", "bne.un", "bne.un.s",
		"bgt", "bgt.s", "bgt.un", "bgt.un.s",
		"bge", "bge.s", "bge.un", "bge.un.s",
		"blt", "blt.s", "blt.un", "blt.un.s",
		"ble", "ble.s", "ble.un", "ble.un.s",
		"leave", "leave.s",
		"b", "bl", "blr", "cbz", "cbnz":
		return true
	}
	// ARM conditional branches: b.eq, b.ne, etc.
	if strings.HasPrefix(mn, "b.") {
		return true
	}
	return false
}

// branchCondition returns a readable condition string for a branch mnemonic.
func branchCondition(mn string) string {
	switch mn {
	case "je", "jz":
		return "zero"
	case "jne", "jnz":
		return "not-zero"
	case "jg", "jnle":
		return "greater"
	case "jge", "jnl":
		return "greater-equal"
	case "jl", "jnge":
		return "less"
	case "jle", "jng":
		return "less-equal"
	case "ja", "jnbe":
		return "above"
	case "jae", "jnb":
		return "above-equal"
	case "jb", "jnae":
		return "below"
	case "jbe", "jna":
		return "below-equal"
	case "js":
		return "sign"
	case "jns":
		return "not-sign"
	case "brtrue", "brtrue.s", "brinst", "brinst.s":
		return "true"
	case "brfalse", "brfalse.s", "brnull", "brnull.s":
		return "false"
	default:
		return mn
	}
}

// condName converts a short condition suffix to a readable expression.
func condName(cond string) string {
	switch cond {
	case "e", "z":
		return "zero"
	case "ne", "nz":
		return "not_zero"
	case "g", "nle":
		return "greater"
	case "ge", "nl":
		return "greater_eq"
	case "l", "nge":
		return "less"
	case "le", "ng":
		return "less_eq"
	case "a", "nbe":
		return "above"
	case "ae", "nb":
		return "above_eq"
	case "b", "nae":
		return "below"
	case "be", "na":
		return "below_eq"
	case "s":
		return "sign"
	case "ns":
		return "not_sign"
	case "o":
		return "overflow"
	case "no":
		return "not_overflow"
	case "p", "pe":
		return "parity"
	case "np", "po":
		return "not_parity"
	case "eq":
		return "equal"
	case "lt":
		return "less"
	case "gt":
		return "greater"
	case "hi":
		return "higher"
	case "lo", "cc":
		return "lower"
	case "ls":
		return "lower_eq"
	case "hs", "cs":
		return "higher_eq"
	case "mi":
		return "negative"
	case "pl":
		return "positive"
	case "vs":
		return "overflow"
	case "vc":
		return "no_overflow"
	}
	return cond
}

// ── Jump condition expression builder ─────────────────────────────────────

// jumpConditionExpr combines a compare/test with a conditional jump into
// a human-readable condition expression.
func jumpConditionExpr(jmpMn, lhs, rhs string, isTest bool) string {
	lhs = regOrVar(lhs)
	rhs = regOrVar(rhs)

	suffix := strings.TrimPrefix(jmpMn, "j")

	if isTest {
		// TEST a, a → bitwise AND, typically "if (a)" or "if (!a)"
		if lhs == rhs {
			switch suffix {
			case "e", "z":
				return fmt.Sprintf("%s == 0", lhs)
			case "ne", "nz":
				return fmt.Sprintf("%s != 0", lhs)
			case "s":
				return fmt.Sprintf("%s < 0", lhs)
			case "ns":
				return fmt.Sprintf("%s >= 0", lhs)
			}
		}
		// TEST a, b → checks bits
		switch suffix {
		case "e", "z":
			return fmt.Sprintf("(%s & %s) == 0", lhs, rhs)
		case "ne", "nz":
			return fmt.Sprintf("(%s & %s) != 0", lhs, rhs)
		default:
			return fmt.Sprintf("test(%s, %s)", lhs, rhs)
		}
	}

	// CMP lhs, rhs
	switch suffix {
	case "e", "z":
		return fmt.Sprintf("%s == %s", lhs, rhs)
	case "ne", "nz":
		return fmt.Sprintf("%s != %s", lhs, rhs)
	case "g", "nle":
		return fmt.Sprintf("%s > %s", lhs, rhs)
	case "ge", "nl":
		return fmt.Sprintf("%s >= %s", lhs, rhs)
	case "l", "nge":
		return fmt.Sprintf("%s < %s", lhs, rhs)
	case "le", "ng":
		return fmt.Sprintf("%s <= %s", lhs, rhs)
	case "a", "nbe":
		return fmt.Sprintf("(unsigned)%s > %s", lhs, rhs)
	case "ae", "nb":
		return fmt.Sprintf("(unsigned)%s >= %s", lhs, rhs)
	case "b", "nae":
		return fmt.Sprintf("(unsigned)%s < %s", lhs, rhs)
	case "be", "na":
		return fmt.Sprintf("(unsigned)%s <= %s", lhs, rhs)
	}

	return fmt.Sprintf("cond_%s(%s, %s)", suffix, lhs, rhs)
}

// ── Branch target parsing ─────────────────────────────────────────────────

// parseBranchTarget attempts to extract a numeric target address from an
// instruction's operand string.
func parseBranchTarget(inst disasm.Instruction) uint64 {
	op := strings.TrimSpace(inst.OpStr)
	if op == "" {
		return 0
	}

	var addr uint64
	if strings.HasPrefix(op, "0x") || strings.HasPrefix(op, "0X") {
		fmt.Sscanf(op, "0x%x", &addr)
		return addr
	}
	// Try plain hex.
	n, _ := fmt.Sscanf(op, "%x", &addr)
	if n == 1 && addr != 0 {
		return addr
	}
	return 0
}

// instIdx returns the global instruction index for a given address, or -1.
func instIdx(a *analysisCtx, addr uint64) int {
	if idx, ok := a.addrToIdx[addr]; ok {
		return idx
	}
	return -1
}
