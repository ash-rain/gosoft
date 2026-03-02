package disasm

import (
	"golang.org/x/arch/arm/armasm"
	"golang.org/x/arch/arm64/arm64asm"
)

type armDisasm struct{ bits int }

func (d *armDisasm) Disassemble(data []byte, startAddr uint64) ([]Instruction, error) {
	var result []Instruction
	offset := 0

	if d.bits == 64 {
		for offset+4 <= len(data) {
			inst, err := arm64asm.Decode(data[offset:])
			if err != nil {
				offset += 4
				continue
			}
			result = append(result, Instruction{
				Address:  startAddr + uint64(offset),
				Bytes:    data[offset : offset+4],
				Mnemonic: inst.Op.String(),
				OpStr:    arm64asm.GNUSyntax(inst),
			})
			offset += 4
		}
	} else {
		for offset+4 <= len(data) {
			inst, err := armasm.Decode(data[offset:], armasm.ModeARM)
			if err != nil {
				offset += 4
				continue
			}
			result = append(result, Instruction{
				Address:  startAddr + uint64(offset),
				Bytes:    data[offset : offset+4],
				Mnemonic: inst.Op.String(),
				OpStr:    armasm.GNUSyntax(inst),
			})
			offset += 4
		}
	}

	return result, nil
}

func (d *armDisasm) Arch() string {
	if d.bits == 64 {
		return "arm64"
	}
	return "arm"
}
