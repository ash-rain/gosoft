package decompiler

import (
	"fmt"
	"strings"

	ctxpkg "godecomp/internal/context"
	"godecomp/internal/disasm"
)

// QuickDecompile generates pseudo-code from disassembly without an AI provider.
// It produces a best-effort skeleton in the given target language by
// translating each instruction into a commented pseudo-statement.
func QuickDecompile(funcCtx *ctxpkg.FunctionContext, lang string) string {
	if funcCtx == nil || len(funcCtx.Disassembly) == 0 {
		return fmt.Sprintf("// No disassembly available for %s\n", funcCtx.FuncName)
	}

	var sb strings.Builder

	// Header / function signature.
	sig := pseudoSignature(funcCtx, lang)
	sb.WriteString(sig)

	// Emit variable declarations section.
	sb.WriteString(pseudoLocals(funcCtx, lang))

	// Body: translate each instruction.
	for _, inst := range funcCtx.Disassembly {
		line := pseudoInstruction(inst, lang)
		sb.WriteString(line)
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
		if lang == "python" {
			indent = "    "
		}
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

// ── Instruction translation ───────────────────────────────────────────────

func pseudoInstruction(inst disasm.Instruction, lang string) string {
	indent := "    "
	comment := commentPrefix(lang)

	mn := strings.ToLower(inst.Mnemonic)
	op := inst.OpStr

	// Generate a pseudo-statement based on instruction mnemonic patterns.
	pseudo := translateMnemonic(mn, op, inst.Address, lang)

	return fmt.Sprintf("%s%s %s 0x%x: %s %s\n",
		indent, pseudo, comment, inst.Address, inst.Mnemonic, op)
}

func translateMnemonic(mn, op string, addr uint64, lang string) string {
	assign := " = "
	semi := ";"
	if lang == "python" || lang == "go" {
		semi = ""
	}
	if lang == "go" {
		assign = " := "
	}

	switch {
	// ── x86 / arm common patterns ─────────────────────────────────────
	case mn == "push":
		return fmt.Sprintf("stack_push(%s)%s", op, semi)
	case mn == "pop":
		return fmt.Sprintf("%s%sstack_pop()%s", op, assign, semi)
	case mn == "ret", mn == "retn":
		return fmt.Sprintf("return%s", semi)
	case mn == "call", mn == "bl", mn == "blr":
		return fmt.Sprintf("%s()%s", sanitizeOp(op), semi)
	case mn == "mov", mn == "movl", mn == "movq",
		mn == "movsx", mn == "movsxd", mn == "movzx":
		parts := splitOperands(op)
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s%s%s", parts[0], assign, parts[1], semi)
		}
		return fmt.Sprintf("mov(%s)%s", op, semi)
	case mn == "lea":
		parts := splitOperands(op)
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s&(%s)%s", parts[0], assign, parts[1], semi)
		}
		return fmt.Sprintf("lea(%s)%s", op, semi)
	case mn == "add":
		parts := splitOperands(op)
		if len(parts) == 2 {
			return fmt.Sprintf("%s += %s%s", parts[0], parts[1], semi)
		}
	case mn == "sub":
		parts := splitOperands(op)
		if len(parts) == 2 {
			return fmt.Sprintf("%s -= %s%s", parts[0], parts[1], semi)
		}
	case mn == "imul", mn == "mul":
		parts := splitOperands(op)
		if len(parts) >= 2 {
			return fmt.Sprintf("%s *= %s%s", parts[0], parts[len(parts)-1], semi)
		}
	case mn == "idiv", mn == "div":
		return fmt.Sprintf("eax, edx = divmod(eax, %s)%s", op, semi)
	case mn == "inc":
		return fmt.Sprintf("%s++%s", op, semi)
	case mn == "dec":
		return fmt.Sprintf("%s--%s", op, semi)
	case mn == "xor":
		parts := splitOperands(op)
		if len(parts) == 2 && parts[0] == parts[1] {
			return fmt.Sprintf("%s%s0%s", parts[0], assign, semi)
		}
		if len(parts) == 2 {
			return fmt.Sprintf("%s ^= %s%s", parts[0], parts[1], semi)
		}
	case mn == "and":
		parts := splitOperands(op)
		if len(parts) == 2 {
			return fmt.Sprintf("%s &= %s%s", parts[0], parts[1], semi)
		}
	case mn == "or":
		parts := splitOperands(op)
		if len(parts) == 2 {
			return fmt.Sprintf("%s |= %s%s", parts[0], parts[1], semi)
		}
	case mn == "shl", mn == "sal":
		parts := splitOperands(op)
		if len(parts) == 2 {
			return fmt.Sprintf("%s <<= %s%s", parts[0], parts[1], semi)
		}
	case mn == "shr", mn == "sar":
		parts := splitOperands(op)
		if len(parts) == 2 {
			return fmt.Sprintf("%s >>= %s%s", parts[0], parts[1], semi)
		}
	case mn == "not":
		return fmt.Sprintf("%s = ~%s%s", op, op, semi)
	case mn == "neg":
		return fmt.Sprintf("%s = -%s%s", op, op, semi)
	case mn == "nop", mn == "endbr64", mn == "endbr32":
		return fmt.Sprintf("/* nop */%s", semi)
	case mn == "test", mn == "cmp", mn == "tst":
		parts := splitOperands(op)
		if len(parts) == 2 {
			return fmt.Sprintf("/* compare %s, %s */%s", parts[0], parts[1], semi)
		}
	case strings.HasPrefix(mn, "j"):
		return fmt.Sprintf("goto %s%s", sanitizeOp(op), semi)
	case strings.HasPrefix(mn, "cmov"):
		parts := splitOperands(op)
		if len(parts) == 2 {
			cond := strings.TrimPrefix(mn, "cmov")
			return fmt.Sprintf("if (%s) %s%s%s%s", cond, parts[0], assign, parts[1], semi)
		}
	case strings.HasPrefix(mn, "set"):
		cond := strings.TrimPrefix(mn, "set")
		return fmt.Sprintf("%s%s(%s ? 1 : 0)%s", op, assign, cond, semi)

	// ── .NET IL opcodes ───────────────────────────────────────────────
	case mn == "ldstr":
		return fmt.Sprintf("stack_push(%s)%s", op, semi)
	case mn == "ldarg.0", mn == "ldarg.1", mn == "ldarg.2", mn == "ldarg.3":
		idx := mn[len(mn)-1:]
		return fmt.Sprintf("stack_push(arg_%s)%s", idx, semi)
	case strings.HasPrefix(mn, "ldarg"):
		return fmt.Sprintf("stack_push(arg_%s)%s", op, semi)
	case mn == "ldloc.0", mn == "ldloc.1", mn == "ldloc.2", mn == "ldloc.3":
		idx := mn[len(mn)-1:]
		return fmt.Sprintf("stack_push(local_%s)%s", idx, semi)
	case strings.HasPrefix(mn, "ldloc"):
		return fmt.Sprintf("stack_push(local_%s)%s", op, semi)
	case mn == "stloc.0", mn == "stloc.1", mn == "stloc.2", mn == "stloc.3":
		idx := mn[len(mn)-1:]
		return fmt.Sprintf("local_%s%sstack_pop()%s", idx, assign, semi)
	case strings.HasPrefix(mn, "stloc"):
		return fmt.Sprintf("local_%s%sstack_pop()%s", op, assign, semi)
	case strings.HasPrefix(mn, "starg"):
		return fmt.Sprintf("arg_%s%sstack_pop()%s", op, assign, semi)
	case strings.HasPrefix(mn, "ldc.i4"):
		val := strings.TrimPrefix(mn, "ldc.i4")
		if val == "" {
			val = op
		} else {
			val = strings.TrimPrefix(val, ".")
		}
		return fmt.Sprintf("stack_push(%s)%s", val, semi)
	case mn == "ldc.i8", mn == "ldc.r4", mn == "ldc.r8":
		return fmt.Sprintf("stack_push(%s)%s", op, semi)
	case mn == "ldnull":
		return fmt.Sprintf("stack_push(null)%s", semi)
	case mn == "dup":
		return fmt.Sprintf("stack_push(stack_peek())%s", semi)
	case mn == "add", mn == "add.ovf":
		return fmt.Sprintf("stack_push(stack_pop() + stack_pop())%s", semi)
	case mn == "sub", mn == "sub.ovf":
		return fmt.Sprintf("stack_push(-stack_pop() + stack_pop())%s", semi)
	case mn == "mul", mn == "mul.ovf":
		return fmt.Sprintf("stack_push(stack_pop() * stack_pop())%s", semi)
	case mn == "div":
		return fmt.Sprintf("stack_push(stack_pop() / stack_pop())%s", semi)
	case mn == "rem":
		return fmt.Sprintf("stack_push(stack_pop() %% stack_pop())%s", semi)
	case strings.HasPrefix(mn, "conv."):
		ty := strings.TrimPrefix(mn, "conv.")
		return fmt.Sprintf("stack_push((%s)stack_pop())%s", ty, semi)
	case mn == "newobj":
		return fmt.Sprintf("stack_push(new %s())%s", sanitizeOp(op), semi)
	case mn == "newarr":
		return fmt.Sprintf("stack_push(new %s[stack_pop()])%s", op, semi)
	case mn == "callvirt", mn == "call":
		return fmt.Sprintf("%s()%s", sanitizeOp(op), semi)
	case mn == "br", mn == "br.s":
		return fmt.Sprintf("goto %s%s", op, semi)
	case mn == "brfalse", mn == "brfalse.s", mn == "brnull", mn == "brnull.s":
		return fmt.Sprintf("if (!stack_pop()) goto %s%s", op, semi)
	case mn == "brtrue", mn == "brtrue.s", mn == "brinst", mn == "brinst.s":
		return fmt.Sprintf("if (stack_pop()) goto %s%s", op, semi)
	case mn == "beq", mn == "beq.s":
		return fmt.Sprintf("if (stack_pop() == stack_pop()) goto %s%s", op, semi)
	case mn == "bne.un", mn == "bne.un.s":
		return fmt.Sprintf("if (stack_pop() != stack_pop()) goto %s%s", op, semi)
	case mn == "bgt", mn == "bgt.s":
		return fmt.Sprintf("if (stack_pop() > stack_pop()) goto %s%s", op, semi)
	case mn == "bge", mn == "bge.s":
		return fmt.Sprintf("if (stack_pop() >= stack_pop()) goto %s%s", op, semi)
	case mn == "blt", mn == "blt.s":
		return fmt.Sprintf("if (stack_pop() < stack_pop()) goto %s%s", op, semi)
	case mn == "ble", mn == "ble.s":
		return fmt.Sprintf("if (stack_pop() <= stack_pop()) goto %s%s", op, semi)
	case mn == "ldfld", mn == "ldsfld":
		return fmt.Sprintf("stack_push(%s)%s", sanitizeOp(op), semi)
	case mn == "stfld", mn == "stsfld":
		return fmt.Sprintf("%s%sstack_pop()%s", sanitizeOp(op), assign, semi)
	case mn == "ldelem", strings.HasPrefix(mn, "ldelem."):
		return fmt.Sprintf("stack_push(arr[stack_pop()])%s", semi)
	case mn == "stelem", strings.HasPrefix(mn, "stelem."):
		return fmt.Sprintf("arr[stack_pop()]%sstack_pop()%s", assign, semi)
	case mn == "ldlen":
		return fmt.Sprintf("stack_push(stack_pop().length)%s", semi)
	case mn == "box":
		return fmt.Sprintf("stack_push(box(%s, stack_pop()))%s", op, semi)
	case mn == "unbox", mn == "unbox.any":
		return fmt.Sprintf("stack_push(unbox<%s>(stack_pop()))%s", op, semi)
	case mn == "castclass":
		return fmt.Sprintf("stack_push((%s)stack_pop())%s", op, semi)
	case mn == "isinst":
		return fmt.Sprintf("stack_push(stack_pop() as %s)%s", op, semi)
	case mn == "throw":
		return fmt.Sprintf("throw stack_pop()%s", semi)
	case mn == "rethrow":
		return fmt.Sprintf("throw%s", semi)
	case mn == "leave", mn == "leave.s":
		return fmt.Sprintf("goto_finally %s%s", op, semi)

	// ── ARM specific ──────────────────────────────────────────────────
	case mn == "stp":
		return fmt.Sprintf("mem_store_pair(%s)%s", op, semi)
	case mn == "ldp":
		return fmt.Sprintf("mem_load_pair(%s)%s", op, semi)
	case mn == "str", mn == "strb", mn == "strh":
		return fmt.Sprintf("mem_store(%s)%s", op, semi)
	case mn == "ldr", mn == "ldrb", mn == "ldrh":
		return fmt.Sprintf("mem_load(%s)%s", op, semi)
	case mn == "adrp", mn == "adr":
		parts := splitOperands(op)
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s%s%s", parts[0], assign, parts[1], semi)
		}
	case mn == "cbz":
		parts := splitOperands(op)
		if len(parts) == 2 {
			return fmt.Sprintf("if (%s == 0) goto %s%s", parts[0], parts[1], semi)
		}
	case mn == "cbnz":
		parts := splitOperands(op)
		if len(parts) == 2 {
			return fmt.Sprintf("if (%s != 0) goto %s%s", parts[0], parts[1], semi)
		}
	case mn == "b", mn == "b.eq", mn == "b.ne",
		mn == "b.lt", mn == "b.gt", mn == "b.le", mn == "b.ge":
		cond := strings.TrimPrefix(mn, "b")
		if cond != "" {
			cond = strings.TrimPrefix(cond, ".")
			return fmt.Sprintf("if (%s) goto %s%s", cond, op, semi)
		}
		return fmt.Sprintf("goto %s%s", op, semi)
	}

	// Fallback: emit as-is with the instruction as a comment.
	return fmt.Sprintf("/* %s %s */%s", mn, op, semi)
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
