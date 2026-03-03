package decompiler

import (
	"fmt"
	"sort"
	"strings"

	ctxpkg "softy/internal/context"
	"softy/internal/disasm"
)

// ── Analysis types ────────────────────────────────────────────────────────

// basicBlock is a contiguous sequence of instructions with a single entry and
// single exit point.
type basicBlock struct {
	id     int
	start  uint64 // address of first instruction
	end    uint64 // address after last instruction
	instrs []disasm.Instruction

	// Successors: fall-through and/or branch target.
	fallThrough *basicBlock
	branchTo    *basicBlock
	branchCond  string // "", "true", condition mnemonic

	// Structural hints set during analysis.
	loopHeader bool
	ifHeader   bool
}

// analysisCtx holds state accumulated during the analysis passes.
type analysisCtx struct {
	funcCtx *ctxpkg.FunctionContext
	lang    string
	blocks  []*basicBlock

	// Maps for resolution.
	addrToBlock  map[uint64]*basicBlock
	addrToIdx    map[uint64]int    // instruction address → index in Disassembly
	labels       map[uint64]string // addr → label name
	symByAddr    map[uint64]string // address → symbol name
	impByAddr    map[uint64]string // address → import name
	stringByAddr map[uint64]string // address → string value

	// Detected variables.
	vars     map[string]string // varName → type hint
	varCount int

	// Prologue/epilogue boundaries.
	prologueEnd   int // index in instructions where prologue ends
	epilogueStart int // index in instructions where epilogue begins
}

func newAnalysisCtx(funcCtx *ctxpkg.FunctionContext, lang string) *analysisCtx {
	a := &analysisCtx{
		funcCtx:      funcCtx,
		lang:         lang,
		addrToBlock:  make(map[uint64]*basicBlock),
		addrToIdx:    make(map[uint64]int),
		labels:       make(map[uint64]string),
		symByAddr:    make(map[uint64]string),
		impByAddr:    make(map[uint64]string),
		stringByAddr: make(map[uint64]string),
		vars:         make(map[string]string),
	}

	// Build symbol lookup.
	for _, s := range funcCtx.Symbols {
		if s.Name != "" {
			a.symByAddr[s.Address] = s.Name
		}
	}
	for _, imp := range funcCtx.Imports {
		if imp.Name != "" {
			a.impByAddr[imp.Address] = imp.Name
		}
	}

	// Build string lookup.
	for _, sr := range funcCtx.Strings {
		if sr.Value != "" {
			a.stringByAddr[sr.Offset] = sr.Value
		}
	}

	// Build address → index lookup.
	for i, inst := range funcCtx.Disassembly {
		a.addrToIdx[inst.Address] = i
	}

	return a
}

// ── Suppress sort import warning ──────────────────────────────────────────
var _ = sort.Ints

// ── Pass 1: Build basic blocks ────────────────────────────────────────────

func (a *analysisCtx) buildBlocks() {
	instrs := a.funcCtx.Disassembly
	if len(instrs) == 0 {
		return
	}

	// Determine block-start addresses: function entry + all branch targets +
	// instructions following branches/jumps.
	starts := map[uint64]bool{instrs[0].Address: true}
	for i, inst := range instrs {
		mn := strings.ToLower(inst.Mnemonic)
		if isBranch(mn) || isJump(mn) {
			target := parseBranchTarget(inst)
			if target != 0 {
				starts[target] = true
			}
			// Instruction after the branch starts a new block.
			if i+1 < len(instrs) {
				starts[instrs[i+1].Address] = true
			}
		}
		if mn == "ret" || mn == "retn" {
			if i+1 < len(instrs) {
				starts[instrs[i+1].Address] = true
			}
		}
	}

	// Split instructions into blocks.
	var curBlock *basicBlock
	blockID := 0
	for _, inst := range instrs {
		if starts[inst.Address] || curBlock == nil {
			if curBlock != nil {
				curBlock.end = inst.Address
				a.blocks = append(a.blocks, curBlock)
			}
			curBlock = &basicBlock{id: blockID, start: inst.Address}
			a.addrToBlock[inst.Address] = curBlock
			blockID++
		}
		curBlock.instrs = append(curBlock.instrs, inst)
	}
	if curBlock != nil && len(curBlock.instrs) > 0 {
		last := curBlock.instrs[len(curBlock.instrs)-1]
		curBlock.end = last.Address + uint64(len(last.Bytes))
		a.blocks = append(a.blocks, curBlock)
	}

	// Wire successors.
	for i, blk := range a.blocks {
		if len(blk.instrs) == 0 {
			continue
		}
		last := blk.instrs[len(blk.instrs)-1]
		mn := strings.ToLower(last.Mnemonic)

		if mn == "ret" || mn == "retn" {
			continue // no successor
		}

		target := parseBranchTarget(last)

		if isUnconditionalJump(mn) {
			blk.branchTo = a.addrToBlock[target]
			blk.branchCond = ""
			continue
		}

		if isBranch(mn) || isConditionalJump(mn) {
			blk.branchTo = a.addrToBlock[target]
			blk.branchCond = branchCondition(mn)
			blk.ifHeader = true
		}

		// Fall-through to next block.
		if i+1 < len(a.blocks) {
			blk.fallThrough = a.blocks[i+1]
		}
	}
}

// ── Pass 2: Generate labels ───────────────────────────────────────────────

func (a *analysisCtx) generateLabels() {
	labelNum := 0
	for _, blk := range a.blocks {
		if len(blk.instrs) == 0 {
			continue
		}
		last := blk.instrs[len(blk.instrs)-1]
		target := parseBranchTarget(last)
		if target != 0 {
			if _, ok := a.labels[target]; !ok {
				a.labels[target] = fmt.Sprintf("L%d", labelNum)
				labelNum++
			}
		}
	}

	// Detect back-edges (loops): if a branch goes to an earlier address.
	for _, blk := range a.blocks {
		if blk.branchTo != nil && blk.branchTo.start <= blk.start {
			blk.branchTo.loopHeader = true
		}
	}
}

// ── Pass 3: Detect prologue/epilogue ──────────────────────────────────────

func (a *analysisCtx) detectPrologueEpilogue() {
	instrs := a.funcCtx.Disassembly
	n := len(instrs)
	a.prologueEnd = 0
	a.epilogueStart = n

	if n == 0 {
		return
	}

	// x86/x64 prologue: push rbp; mov rbp, rsp; sub rsp, N
	// Also: endbr64/endbr32 prefix
	for i := 0; i < n && i < 5; i++ {
		mn := strings.ToLower(instrs[i].Mnemonic)
		op := strings.ToLower(instrs[i].OpStr)
		if mn == "endbr64" || mn == "endbr32" {
			a.prologueEnd = i + 1
			continue
		}
		if mn == "push" && (strings.Contains(op, "rbp") || strings.Contains(op, "ebp")) {
			a.prologueEnd = i + 1
			continue
		}
		if mn == "mov" && (strings.Contains(op, "rbp") || strings.Contains(op, "ebp")) &&
			(strings.Contains(op, "rsp") || strings.Contains(op, "esp")) {
			a.prologueEnd = i + 1
			continue
		}
		if mn == "sub" && (strings.Contains(op, "rsp") || strings.Contains(op, "esp")) {
			a.prologueEnd = i + 1
			break
		}
		// ARM prologue: stp x29, x30, [sp, ...]
		if mn == "stp" && strings.Contains(op, "x29") {
			a.prologueEnd = i + 1
			continue
		}
		if mn == "mov" && strings.Contains(op, "x29") && strings.Contains(op, "sp") {
			a.prologueEnd = i + 1
			break
		}
		break
	}

	// Epilogue: pop rbp; ret (or ldp x29, x30; ret)
	for i := n - 1; i >= 0 && i > n-5; i-- {
		mn := strings.ToLower(instrs[i].Mnemonic)
		op := strings.ToLower(instrs[i].OpStr)
		if mn == "ret" || mn == "retn" {
			a.epilogueStart = i
			continue
		}
		if mn == "pop" && (strings.Contains(op, "rbp") || strings.Contains(op, "ebp")) {
			a.epilogueStart = i
			continue
		}
		if mn == "leave" {
			a.epilogueStart = i
			continue
		}
		if mn == "ldp" && strings.Contains(op, "x29") {
			a.epilogueStart = i
			continue
		}
		break
	}
}

// ── Pass 4: Track registers & emit variables ──────────────────────────────

// resolveCallTarget returns a human-readable name for a call target address/operand.
func (a *analysisCtx) resolveCallTarget(op string) string {
	op = strings.TrimSpace(op)

	// Try to parse as hex address.
	var addr uint64
	if strings.HasPrefix(op, "0x") || strings.HasPrefix(op, "0X") {
		fmt.Sscanf(op, "0x%x", &addr)
	} else {
		fmt.Sscanf(op, "%x", &addr)
	}

	if addr != 0 {
		if name, ok := a.symByAddr[addr]; ok {
			return sanitizeName(name)
		}
		if name, ok := a.impByAddr[addr]; ok {
			return sanitizeName(name)
		}
	}

	// Already a symbolic name.
	return sanitizeName(op)
}

func (a *analysisCtx) newVar(hint string) string {
	a.varCount++
	name := fmt.Sprintf("var_%d", a.varCount)
	a.vars[name] = hint
	return name
}

// ── Main emitter ──────────────────────────────────────────────────────────

func emitBlock(a *analysisCtx, blk *basicBlock, sb *strings.Builder, indent int) {
	pad := strings.Repeat("    ", indent)
	comment := commentPrefix(a.lang)
	semi := langSemicolon(a.lang)

	// Label if targeted.
	if label, ok := a.labels[blk.start]; ok {
		if blk.loopHeader {
			sb.WriteString(fmt.Sprintf("\n%s%s %s (loop)\n", pad, comment, label))
		}
		sb.WriteString(fmt.Sprintf("%s%s:\n", labelIndent(a.lang, pad), label))
	}

	instrs := blk.instrs
	n := len(instrs)

	for i := 0; i < n; i++ {
		inst := instrs[i]

		// Skip prologue/epilogue instructions.
		globalIdx := instIdx(a, inst.Address)
		if globalIdx >= 0 && globalIdx < a.prologueEnd {
			continue
		}
		if globalIdx >= a.epilogueStart {
			if strings.ToLower(inst.Mnemonic) == "ret" || strings.ToLower(inst.Mnemonic) == "retn" {
				sb.WriteString(fmt.Sprintf("%sreturn%s\n", pad, semi))
			}
			continue
		}

		mn := strings.ToLower(inst.Mnemonic)
		op := inst.OpStr
		parts := splitOperands(op)

		// Try combined patterns first (cmp + conditional jump).
		if i+1 < n && (mn == "cmp" || mn == "test") && len(parts) == 2 {
			next := instrs[i+1]
			nmn := strings.ToLower(next.Mnemonic)
			if isConditionalJump(nmn) {
				cond := jumpConditionExpr(nmn, parts[0], parts[1], mn == "test")
				target := parseBranchTarget(next)
				label := a.labels[target]
				if label == "" {
					label = fmt.Sprintf("0x%x", target)
				}
				tb := a.addrToBlock[target]
				// Check if this looks like an if-else pattern.
				if tb != nil && tb.loopHeader {
					sb.WriteString(fmt.Sprintf("%swhile (%s) { %s loop %s\n", pad, cond, comment, label))
				} else {
					sb.WriteString(fmt.Sprintf("%sif (%s) goto %s%s\n", pad, cond, label, semi))
				}
				i++ // skip the jump instruction
				continue
			}
		}

		line := emitInstruction(a, inst, pad, semi)
		sb.WriteString(line)
	}
}

func emitInstruction(a *analysisCtx, inst disasm.Instruction, pad, semi string) string {
	comment := commentPrefix(a.lang)
	mn := strings.ToLower(inst.Mnemonic)
	op := inst.OpStr
	parts := splitOperands(op)
	assign := langAssign(a.lang)

	switch {
	// ── nop / alignment ───────────────────────────────────────────────
	case mn == "nop", mn == "endbr64", mn == "endbr32", mn == "int3",
		mn == "ud2", mn == "hlt":
		return "" // suppress noise

	// ── stack ─────────────────────────────────────────────────────────
	case mn == "push":
		// Only show non-prologue pushes.
		return fmt.Sprintf("%ssave %s%s %s push %s\n", pad, op, semi, comment, op)
	case mn == "pop":
		return fmt.Sprintf("%srestore %s%s %s pop %s\n", pad, op, semi, comment, op)

	// ── return ────────────────────────────────────────────────────────
	case mn == "ret", mn == "retn":
		return fmt.Sprintf("%sreturn%s\n", pad, semi)

	// ── calls ─────────────────────────────────────────────────────────
	case mn == "call", mn == "bl", mn == "blr", mn == "callvirt":
		target := a.resolveCallTarget(op)
		return fmt.Sprintf("%s%s()%s\n", pad, target, semi)

	// ── mov family ────────────────────────────────────────────────────
	case mn == "mov", mn == "movl", mn == "movq",
		mn == "movsx", mn == "movsxd", mn == "movzx",
		mn == "movss", mn == "movsd", mn == "movaps", mn == "movups":
		if len(parts) == 2 {
			dst := regOrVar(parts[0])
			src := regOrVar(parts[1])
			return fmt.Sprintf("%s%s%s%s%s %s %s\n", pad, dst, assign, src, semi, comment, mn)
		}
		return fmt.Sprintf("%smov(%s)%s\n", pad, op, semi)

	case mn == "lea":
		if len(parts) == 2 {
			dst := regOrVar(parts[0])
			src := parts[1]
			return fmt.Sprintf("%s%s%s&(%s)%s %s lea\n", pad, dst, assign, src, semi, comment)
		}

	// ── arithmetic ────────────────────────────────────────────────────
	case mn == "add":
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s += %s%s\n", pad, regOrVar(parts[0]), regOrVar(parts[1]), semi)
		}
	case mn == "sub":
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s -= %s%s\n", pad, regOrVar(parts[0]), regOrVar(parts[1]), semi)
		}
	case mn == "imul", mn == "mul":
		if len(parts) >= 2 {
			return fmt.Sprintf("%s%s *= %s%s\n", pad, regOrVar(parts[0]), regOrVar(parts[len(parts)-1]), semi)
		}
	case mn == "idiv", mn == "div":
		return fmt.Sprintf("%squot, rem %s divmod(%s)%s\n", pad, assign, op, semi)
	case mn == "inc":
		return fmt.Sprintf("%s%s++%s\n", pad, regOrVar(op), semi)
	case mn == "dec":
		return fmt.Sprintf("%s%s--%s\n", pad, regOrVar(op), semi)
	case mn == "neg":
		return fmt.Sprintf("%s%s %s -%s%s\n", pad, regOrVar(op), assign, regOrVar(op), semi)
	case mn == "not":
		return fmt.Sprintf("%s%s %s ~%s%s\n", pad, regOrVar(op), assign, regOrVar(op), semi)

	// ── bitwise ───────────────────────────────────────────────────────
	case mn == "xor":
		if len(parts) == 2 && parts[0] == parts[1] {
			return fmt.Sprintf("%s%s%s0%s %s zero\n", pad, regOrVar(parts[0]), assign, semi, comment)
		}
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s ^= %s%s\n", pad, regOrVar(parts[0]), regOrVar(parts[1]), semi)
		}
	case mn == "and":
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s &= %s%s\n", pad, regOrVar(parts[0]), regOrVar(parts[1]), semi)
		}
	case mn == "or":
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s |= %s%s\n", pad, regOrVar(parts[0]), regOrVar(parts[1]), semi)
		}
	case mn == "shl", mn == "sal":
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s <<= %s%s\n", pad, regOrVar(parts[0]), regOrVar(parts[1]), semi)
		}
	case mn == "shr":
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s >>= %s%s %s unsigned\n", pad, regOrVar(parts[0]), regOrVar(parts[1]), semi, comment)
		}
	case mn == "sar":
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s >>= %s%s %s signed\n", pad, regOrVar(parts[0]), regOrVar(parts[1]), semi, comment)
		}

	// ── compare / test ────────────────────────────────────────────────
	case mn == "cmp", mn == "tst", mn == "test":
		// Standalone compare (not merged with following jump).
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s compare(%s, %s)\n", pad, comment, regOrVar(parts[0]), regOrVar(parts[1]))
		}

	// ── conditional moves ─────────────────────────────────────────────
	case strings.HasPrefix(mn, "cmov"):
		if len(parts) == 2 {
			cond := condName(strings.TrimPrefix(mn, "cmov"))
			return fmt.Sprintf("%sif (%s) %s%s%s%s\n", pad, cond, regOrVar(parts[0]), assign, regOrVar(parts[1]), semi)
		}
	case strings.HasPrefix(mn, "set"):
		cond := condName(strings.TrimPrefix(mn, "set"))
		return fmt.Sprintf("%s%s%s%s ? 1 : 0%s\n", pad, regOrVar(op), assign, cond, semi)

	// ── jumps ─────────────────────────────────────────────────────────
	case isUnconditionalJump(mn):
		target := parseBranchTarget(inst)
		label := a.labels[target]
		if label == "" {
			label = sanitizeOp(op)
		}
		return fmt.Sprintf("%sgoto %s%s\n", pad, label, semi)
	case isConditionalJump(mn):
		target := parseBranchTarget(inst)
		label := a.labels[target]
		if label == "" {
			label = sanitizeOp(op)
		}
		cond := condName(strings.TrimPrefix(mn, "j"))
		return fmt.Sprintf("%sif (%s) goto %s%s\n", pad, cond, label, semi)

	// ── .NET IL opcodes ───────────────────────────────────────────────
	case mn == "ldstr":
		return fmt.Sprintf("%sstack.push(%s)%s\n", pad, op, semi)
	case mn == "ldarg.0":
		return fmt.Sprintf("%sstack.push(this)%s %s ldarg.0\n", pad, semi, comment)
	case mn == "ldarg.1", mn == "ldarg.2", mn == "ldarg.3":
		idx := mn[len(mn)-1:]
		return fmt.Sprintf("%sstack.push(arg%s)%s\n", pad, idx, semi)
	case strings.HasPrefix(mn, "ldarg"):
		return fmt.Sprintf("%sstack.push(arg_%s)%s\n", pad, op, semi)
	case mn == "ldloc.0", mn == "ldloc.1", mn == "ldloc.2", mn == "ldloc.3":
		idx := mn[len(mn)-1:]
		return fmt.Sprintf("%sstack.push(v%s)%s\n", pad, idx, semi)
	case strings.HasPrefix(mn, "ldloc"):
		return fmt.Sprintf("%sstack.push(v_%s)%s\n", pad, op, semi)
	case mn == "stloc.0", mn == "stloc.1", mn == "stloc.2", mn == "stloc.3":
		idx := mn[len(mn)-1:]
		return fmt.Sprintf("%sv%s%sstack.pop()%s\n", pad, idx, assign, semi)
	case strings.HasPrefix(mn, "stloc"):
		return fmt.Sprintf("%sv_%s%sstack.pop()%s\n", pad, op, assign, semi)
	case strings.HasPrefix(mn, "starg"):
		return fmt.Sprintf("%sarg_%s%sstack.pop()%s\n", pad, op, assign, semi)
	case strings.HasPrefix(mn, "ldc.i4"):
		val := strings.TrimPrefix(mn, "ldc.i4")
		if val == "" {
			val = op
		} else {
			val = strings.TrimPrefix(val, ".")
		}
		return fmt.Sprintf("%sstack.push(%s)%s\n", pad, val, semi)
	case mn == "ldc.i8", mn == "ldc.r4", mn == "ldc.r8":
		return fmt.Sprintf("%sstack.push(%s)%s\n", pad, op, semi)
	case mn == "ldnull":
		return fmt.Sprintf("%sstack.push(null)%s\n", pad, semi)
	case mn == "dup":
		return fmt.Sprintf("%sstack.push(stack.peek())%s\n", pad, semi)
	case mn == "pop":
		return fmt.Sprintf("%sstack.pop()%s %s discard\n", pad, semi, comment)
	case mn == "add.ovf", mn == "add.ovf.un":
		return fmt.Sprintf("%sstack.push(checked(stack.pop() + stack.pop()))%s\n", pad, semi)
	case mn == "sub.ovf", mn == "sub.ovf.un":
		return fmt.Sprintf("%sstack.push(checked(stack.pop() - stack.pop()))%s\n", pad, semi)
	case mn == "mul.ovf", mn == "mul.ovf.un":
		return fmt.Sprintf("%sstack.push(checked(stack.pop() * stack.pop()))%s\n", pad, semi)
	case mn == "div", mn == "div.un":
		return fmt.Sprintf("%sstack.push(stack.pop() / stack.pop())%s\n", pad, semi)
	case mn == "rem", mn == "rem.un":
		return fmt.Sprintf("%sstack.push(stack.pop() %% stack.pop())%s\n", pad, semi)
	case strings.HasPrefix(mn, "conv."):
		ty := ilTypeMap(strings.TrimPrefix(mn, "conv."))
		return fmt.Sprintf("%sstack.push((%s)stack.pop())%s\n", pad, ty, semi)
	case mn == "newobj":
		return fmt.Sprintf("%sstack.push(new %s())%s\n", pad, sanitizeOp(op), semi)
	case mn == "newarr":
		return fmt.Sprintf("%sstack.push(new %s[stack.pop()])%s\n", pad, op, semi)
	case mn == "call":
		return fmt.Sprintf("%s%s()%s\n", pad, sanitizeOp(op), semi)
	case mn == "br", mn == "br.s":
		label := a.labels[parseBranchTarget(inst)]
		if label == "" {
			label = op
		}
		return fmt.Sprintf("%sgoto %s%s\n", pad, label, semi)
	case mn == "brfalse", mn == "brfalse.s", mn == "brnull", mn == "brnull.s":
		label := a.labels[parseBranchTarget(inst)]
		if label == "" {
			label = op
		}
		return fmt.Sprintf("%sif (!stack.pop()) goto %s%s\n", pad, label, semi)
	case mn == "brtrue", mn == "brtrue.s", mn == "brinst", mn == "brinst.s":
		label := a.labels[parseBranchTarget(inst)]
		if label == "" {
			label = op
		}
		return fmt.Sprintf("%sif (stack.pop()) goto %s%s\n", pad, label, semi)
	case mn == "beq", mn == "beq.s":
		return emitILBranch(a, inst, "==", pad, semi)
	case mn == "bne.un", mn == "bne.un.s":
		return emitILBranch(a, inst, "!=", pad, semi)
	case mn == "bgt", mn == "bgt.s", mn == "bgt.un", mn == "bgt.un.s":
		return emitILBranch(a, inst, ">", pad, semi)
	case mn == "bge", mn == "bge.s", mn == "bge.un", mn == "bge.un.s":
		return emitILBranch(a, inst, ">=", pad, semi)
	case mn == "blt", mn == "blt.s", mn == "blt.un", mn == "blt.un.s":
		return emitILBranch(a, inst, "<", pad, semi)
	case mn == "ble", mn == "ble.s", mn == "ble.un", mn == "ble.un.s":
		return emitILBranch(a, inst, "<=", pad, semi)
	case mn == "ceq":
		return fmt.Sprintf("%sstack.push(stack.pop() == stack.pop() ? 1 : 0)%s\n", pad, semi)
	case mn == "cgt", mn == "cgt.un":
		return fmt.Sprintf("%sstack.push(stack.pop() > stack.pop() ? 1 : 0)%s\n", pad, semi)
	case mn == "clt", mn == "clt.un":
		return fmt.Sprintf("%sstack.push(stack.pop() < stack.pop() ? 1 : 0)%s\n", pad, semi)
	case mn == "ldfld", mn == "ldsfld":
		return fmt.Sprintf("%sstack.push(%s)%s\n", pad, sanitizeOp(op), semi)
	case mn == "stfld", mn == "stsfld":
		return fmt.Sprintf("%s%s%sstack.pop()%s\n", pad, sanitizeOp(op), assign, semi)
	case mn == "ldelem", strings.HasPrefix(mn, "ldelem."):
		return fmt.Sprintf("%sstack.push(arr[stack.pop()])%s\n", pad, semi)
	case mn == "stelem", strings.HasPrefix(mn, "stelem."):
		return fmt.Sprintf("%sarr[stack.pop()]%sstack.pop()%s\n", pad, assign, semi)
	case mn == "ldlen":
		return fmt.Sprintf("%sstack.push(stack.pop().Length)%s\n", pad, semi)
	case mn == "box":
		return fmt.Sprintf("%sstack.push((%s)stack.pop())%s %s box\n", pad, op, semi, comment)
	case mn == "unbox", mn == "unbox.any":
		return fmt.Sprintf("%sstack.push((%s)stack.pop())%s %s unbox\n", pad, op, semi, comment)
	case mn == "castclass":
		return fmt.Sprintf("%sstack.push((%s)stack.pop())%s\n", pad, op, semi)
	case mn == "isinst":
		return fmt.Sprintf("%sstack.push(stack.pop() as %s)%s\n", pad, op, semi)
	case mn == "throw":
		return fmt.Sprintf("%sthrow stack.pop()%s\n", pad, semi)
	case mn == "rethrow":
		return fmt.Sprintf("%sthrow%s %s rethrow\n", pad, semi, comment)
	case mn == "leave", mn == "leave.s":
		label := a.labels[parseBranchTarget(inst)]
		if label == "" {
			label = op
		}
		return fmt.Sprintf("%sgoto %s%s %s end-try\n", pad, label, semi, comment)
	case mn == "ldtoken":
		return fmt.Sprintf("%sstack.push(typeof(%s))%s\n", pad, op, semi)
	case mn == "initobj":
		return fmt.Sprintf("%s*stack.pop()%sdefault(%s)%s\n", pad, assign, op, semi)
	case mn == "sizeof":
		return fmt.Sprintf("%sstack.push(sizeof(%s))%s\n", pad, op, semi)

	// ── ARM specific ──────────────────────────────────────────────────
	case mn == "stp":
		return fmt.Sprintf("%smem[sp] %s {%s}%s %s store pair\n", pad, assign, op, semi, comment)
	case mn == "ldp":
		return fmt.Sprintf("%s{%s} %s mem[sp]%s %s load pair\n", pad, op, assign, semi, comment)
	case mn == "str", mn == "strb", mn == "strh", mn == "stur":
		if len(parts) >= 2 {
			return fmt.Sprintf("%smem[%s]%s%s%s\n", pad, strings.TrimSpace(parts[1]), assign, regOrVar(parts[0]), semi)
		}
		return fmt.Sprintf("%smem_store(%s)%s\n", pad, op, semi)
	case mn == "ldr", mn == "ldrb", mn == "ldrh", mn == "ldur":
		if len(parts) >= 2 {
			return fmt.Sprintf("%s%s%smem[%s]%s\n", pad, regOrVar(parts[0]), assign, strings.TrimSpace(parts[1]), semi)
		}
		return fmt.Sprintf("%smem_load(%s)%s\n", pad, op, semi)
	case mn == "adrp", mn == "adr":
		if len(parts) == 2 {
			return fmt.Sprintf("%s%s%s%s%s %s page addr\n", pad, regOrVar(parts[0]), assign, parts[1], semi, comment)
		}
	case mn == "cbz":
		if len(parts) == 2 {
			target := parseBranchTarget(inst)
			label := a.labels[target]
			if label == "" {
				label = strings.TrimSpace(parts[1])
			}
			return fmt.Sprintf("%sif (%s == 0) goto %s%s\n", pad, regOrVar(parts[0]), label, semi)
		}
	case mn == "cbnz":
		if len(parts) == 2 {
			target := parseBranchTarget(inst)
			label := a.labels[target]
			if label == "" {
				label = strings.TrimSpace(parts[1])
			}
			return fmt.Sprintf("%sif (%s != 0) goto %s%s\n", pad, regOrVar(parts[0]), label, semi)
		}
	case mn == "b":
		target := parseBranchTarget(inst)
		label := a.labels[target]
		if label == "" {
			label = sanitizeOp(op)
		}
		return fmt.Sprintf("%sgoto %s%s\n", pad, label, semi)
	case strings.HasPrefix(mn, "b."):
		cond := condName(strings.TrimPrefix(mn, "b."))
		target := parseBranchTarget(inst)
		label := a.labels[target]
		if label == "" {
			label = sanitizeOp(op)
		}
		return fmt.Sprintf("%sif (%s) goto %s%s\n", pad, cond, label, semi)
	}

	// ── Fallback ──────────────────────────────────────────────────────
	return fmt.Sprintf("%s%s %s %s %s\n", pad, comment, mn, op, comment)
}

// ── IL helper ─────────────────────────────────────────────────────────────

func emitILBranch(a *analysisCtx, inst disasm.Instruction, oper, pad, semi string) string {
	target := parseBranchTarget(inst)
	label := a.labels[target]
	if label == "" {
		label = inst.OpStr
	}
	return fmt.Sprintf("%sif (stack.pop() %s stack.pop()) goto %s%s\n", pad, oper, label, semi)
}

func ilTypeMap(raw string) string {
	switch raw {
	case "i1":
		return "sbyte"
	case "i2":
		return "short"
	case "i4":
		return "int"
	case "i8":
		return "long"
	case "u1":
		return "byte"
	case "u2":
		return "ushort"
	case "u4":
		return "uint"
	case "u8":
		return "ulong"
	case "r4":
		return "float"
	case "r8":
		return "double"
	case "r.un":
		return "float"
	default:
		return raw
	}
}
