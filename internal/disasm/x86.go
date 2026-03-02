package disasm

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

type x86Disasm struct {
	bits int // 32 or 64
}

func (d *x86Disasm) Disassemble(data []byte, startAddr uint64) ([]Instruction, error) {
	var result []Instruction
	offset := 0
	for offset < len(data) {
		inst, err := x86asm.Decode(data[offset:], d.bits)
		if err != nil {
			// Skip one byte on decode error
			offset++
			continue
		}
		if inst.Len == 0 {
			offset++
			continue
		}

		end := offset + inst.Len
		if end > len(data) {
			end = len(data)
		}

		result = append(result, Instruction{
			Address:  startAddr + uint64(offset),
			Bytes:    data[offset:end],
			Mnemonic: inst.Op.String(),
			OpStr:    x86asm.IntelSyntax(inst, startAddr+uint64(offset), nil),
		})
		offset += inst.Len
	}
	return result, nil
}

func (d *x86Disasm) Arch() string {
	if d.bits == 64 {
		return "x86_64"
	}
	return "x86"
}

// formatX86Inst formats an instruction for display (used internally).
func formatX86Inst(inst x86asm.Inst, addr uint64) string {
	return fmt.Sprintf("%s", x86asm.IntelSyntax(inst, addr, nil))
}
