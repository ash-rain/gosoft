package disasm

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ilDisasm implements the Disassembler interface for .NET CIL/MSIL bytecode.
type ilDisasm struct{}

func (d *ilDisasm) Arch() string { return "il" }

// Disassemble parses CIL IL bytecode and returns instructions.
func (d *ilDisasm) Disassemble(data []byte, startAddr uint64) ([]Instruction, error) {
	var instructions []Instruction
	pc := 0

	for pc < len(data) {
		addr := startAddr + uint64(pc)
		opByte := data[pc]
		pc++

		var mnemonic, opStr string
		var operandSize int

		if opByte == 0xFE && pc < len(data) {
			// Two-byte opcode
			op2 := data[pc]
			pc++
			mnemonic, operandSize = ilTwoByteOp(op2)
			if mnemonic == "" {
				mnemonic = fmt.Sprintf("0xFE.%02X", op2)
			}
		} else {
			mnemonic, operandSize = ilOneByteOp(opByte)
			if mnemonic == "" {
				mnemonic = fmt.Sprintf("0x%02X", opByte)
			}
		}

		// Read operand
		rawBytes := []byte{opByte}

		if operandSize > 0 {
			if pc+operandSize > len(data) {
				break
			}
			operandData := data[pc : pc+operandSize]
			rawBytes = append(rawBytes, operandData...)
			opStr = formatILOperand(mnemonic, operandData, addr+uint64(pc-int(startAddr)))
			pc += operandSize
		} else if operandSize == -1 {
			// switch table: uint32 N, then N int32 offsets
			if pc+4 > len(data) {
				break
			}
			n := binary.LittleEndian.Uint32(data[pc : pc+4])
			rawBytes = append(rawBytes, data[pc:pc+4]...)
			pc += 4
			targets := make([]string, 0, n)
			for i := uint32(0); i < n && pc+4 <= len(data); i++ {
				delta := int32(binary.LittleEndian.Uint32(data[pc : pc+4]))
				rawBytes = append(rawBytes, data[pc:pc+4]...)
				target := int64(addr) + int64(pc+4) + int64(delta)
				targets = append(targets, fmt.Sprintf("0x%X", target))
				pc += 4
			}
			opStr = fmt.Sprintf("[%s]", strings.Join(targets, ", "))
		}

		instructions = append(instructions, Instruction{
			Address:  addr,
			Bytes:    rawBytes,
			Mnemonic: mnemonic,
			OpStr:    opStr,
		})
	}

	return instructions, nil
}

// formatILOperand formats the operand for display.
func formatILOperand(mnemonic string, data []byte, nextPC uint64) string {
	if len(data) == 0 {
		return ""
	}

	switch len(data) {
	case 1:
		// Byte operand
		switch mnemonic {
		case "ldc.i4.s":
			return fmt.Sprintf("%d", int8(data[0]))
		case "br.s", "brfalse.s", "brtrue.s",
			"beq.s", "bge.s", "bgt.s", "ble.s", "blt.s",
			"bne.un.s", "bge.un.s", "bgt.un.s", "ble.un.s", "blt.un.s":
			target := int64(nextPC) + int64(int8(data[0]))
			return fmt.Sprintf("IL_%04X", target)
		default:
			return fmt.Sprintf("%d", data[0])
		}

	case 2:
		val := binary.LittleEndian.Uint16(data)
		return fmt.Sprintf("%d", val)

	case 4:
		val := binary.LittleEndian.Uint32(data)
		switch mnemonic {
		case "br", "brfalse", "brtrue",
			"beq", "bge", "bgt", "ble", "blt",
			"bne.un", "bge.un", "bgt.un", "ble.un", "blt.un",
			"leave", "leave.s":
			target := int64(nextPC) + int64(int32(val))
			return fmt.Sprintf("IL_%04X", target)
		case "call", "callvirt", "ldftn", "ldvirtftn",
			"jmp", "calli":
			return fmt.Sprintf("0x%08X", val)
		case "ldstr":
			return fmt.Sprintf("0x%08X // user string token", val)
		case "ldfld", "ldflda", "stfld", "ldsfld", "ldsflda", "stsfld":
			return fmt.Sprintf("0x%08X // field token", val)
		case "newobj", "castclass", "isinst", "box", "unbox", "unbox.any",
			"newarr", "initobj", "constrained.", "sizeof", "ldtoken",
			"stelem", "ldelem", "ldobj", "stobj", "mkrefany", "refanyval":
			return fmt.Sprintf("0x%08X // type token", val)
		case "ldc.i4":
			return fmt.Sprintf("%d", int32(val))
		default:
			return fmt.Sprintf("0x%08X", val)
		}

	case 8:
		val := binary.LittleEndian.Uint64(data)
		if mnemonic == "ldc.i8" {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("0x%016X", val)
	}
	return fmt.Sprintf("(% 02X)", data)
}

// ilOneByteOp returns the mnemonic and operand size for a single-byte IL opcode.
// operandSize: 0=none, 1=byte, 2=int16, 4=int32, 8=int64, -1=switch
func ilOneByteOp(op byte) (string, int) {
	switch op {
	case 0x00:
		return "nop", 0
	case 0x01:
		return "break", 0
	case 0x02:
		return "ldarg.0", 0
	case 0x03:
		return "ldarg.1", 0
	case 0x04:
		return "ldarg.2", 0
	case 0x05:
		return "ldarg.3", 0
	case 0x06:
		return "ldloc.0", 0
	case 0x07:
		return "ldloc.1", 0
	case 0x08:
		return "ldloc.2", 0
	case 0x09:
		return "ldloc.3", 0
	case 0x0A:
		return "stloc.0", 0
	case 0x0B:
		return "stloc.1", 0
	case 0x0C:
		return "stloc.2", 0
	case 0x0D:
		return "stloc.3", 0
	case 0x0E:
		return "ldarg.s", 1
	case 0x0F:
		return "ldarga.s", 1
	case 0x10:
		return "starg.s", 1
	case 0x11:
		return "ldloc.s", 1
	case 0x12:
		return "ldloca.s", 1
	case 0x13:
		return "stloc.s", 1
	case 0x14:
		return "ldnull", 0
	case 0x15:
		return "ldc.i4.m1", 0
	case 0x16:
		return "ldc.i4.0", 0
	case 0x17:
		return "ldc.i4.1", 0
	case 0x18:
		return "ldc.i4.2", 0
	case 0x19:
		return "ldc.i4.3", 0
	case 0x1A:
		return "ldc.i4.4", 0
	case 0x1B:
		return "ldc.i4.5", 0
	case 0x1C:
		return "ldc.i4.6", 0
	case 0x1D:
		return "ldc.i4.7", 0
	case 0x1E:
		return "ldc.i4.8", 0
	case 0x1F:
		return "ldc.i4.s", 1
	case 0x20:
		return "ldc.i4", 4
	case 0x21:
		return "ldc.i8", 8
	case 0x22:
		return "ldc.r4", 4
	case 0x23:
		return "ldc.r8", 8
	case 0x25:
		return "dup", 0
	case 0x26:
		return "pop", 0
	case 0x27:
		return "jmp", 4
	case 0x28:
		return "call", 4
	case 0x29:
		return "calli", 4
	case 0x2A:
		return "ret", 0
	case 0x2B:
		return "br.s", 1
	case 0x2C:
		return "brfalse.s", 1
	case 0x2D:
		return "brtrue.s", 1
	case 0x2E:
		return "beq.s", 1
	case 0x2F:
		return "bge.s", 1
	case 0x30:
		return "bgt.s", 1
	case 0x31:
		return "ble.s", 1
	case 0x32:
		return "blt.s", 1
	case 0x33:
		return "bne.un.s", 1
	case 0x34:
		return "bge.un.s", 1
	case 0x35:
		return "bgt.un.s", 1
	case 0x36:
		return "ble.un.s", 1
	case 0x37:
		return "blt.un.s", 1
	case 0x38:
		return "br", 4
	case 0x39:
		return "brfalse", 4
	case 0x3A:
		return "brtrue", 4
	case 0x3B:
		return "beq", 4
	case 0x3C:
		return "bge", 4
	case 0x3D:
		return "bgt", 4
	case 0x3E:
		return "ble", 4
	case 0x3F:
		return "blt", 4
	case 0x40:
		return "bne.un", 4
	case 0x41:
		return "bge.un", 4
	case 0x42:
		return "bgt.un", 4
	case 0x43:
		return "ble.un", 4
	case 0x44:
		return "blt.un", 4
	case 0x45:
		return "switch", -1
	case 0x46:
		return "ldind.i1", 0
	case 0x47:
		return "ldind.u1", 0
	case 0x48:
		return "ldind.i2", 0
	case 0x49:
		return "ldind.u2", 0
	case 0x4A:
		return "ldind.i4", 0
	case 0x4B:
		return "ldind.u4", 0
	case 0x4C:
		return "ldind.i8", 0
	case 0x4D:
		return "ldind.i", 0
	case 0x4E:
		return "ldind.r4", 0
	case 0x4F:
		return "ldind.r8", 0
	case 0x50:
		return "ldind.ref", 0
	case 0x51:
		return "stind.ref", 0
	case 0x52:
		return "stind.i1", 0
	case 0x53:
		return "stind.i2", 0
	case 0x54:
		return "stind.i4", 0
	case 0x55:
		return "stind.i8", 0
	case 0x56:
		return "stind.r4", 0
	case 0x57:
		return "stind.r8", 0
	case 0x58:
		return "add", 0
	case 0x59:
		return "sub", 0
	case 0x5A:
		return "mul", 0
	case 0x5B:
		return "div", 0
	case 0x5C:
		return "div.un", 0
	case 0x5D:
		return "rem", 0
	case 0x5E:
		return "rem.un", 0
	case 0x5F:
		return "and", 0
	case 0x60:
		return "or", 0
	case 0x61:
		return "xor", 0
	case 0x62:
		return "shl", 0
	case 0x63:
		return "shr", 0
	case 0x64:
		return "shr.un", 0
	case 0x65:
		return "neg", 0
	case 0x66:
		return "not", 0
	case 0x67:
		return "conv.i1", 0
	case 0x68:
		return "conv.i2", 0
	case 0x69:
		return "conv.i4", 0
	case 0x6A:
		return "conv.i8", 0
	case 0x6B:
		return "conv.r4", 0
	case 0x6C:
		return "conv.r8", 0
	case 0x6D:
		return "conv.u4", 0
	case 0x6E:
		return "conv.u8", 0
	case 0x6F:
		return "callvirt", 4
	case 0x70:
		return "cpobj", 4
	case 0x71:
		return "ldobj", 4
	case 0x72:
		return "ldstr", 4
	case 0x73:
		return "newobj", 4
	case 0x74:
		return "castclass", 4
	case 0x75:
		return "isinst", 4
	case 0x76:
		return "conv.r.un", 0
	case 0x79:
		return "unbox", 4
	case 0x7A:
		return "throw", 0
	case 0x7B:
		return "ldfld", 4
	case 0x7C:
		return "ldflda", 4
	case 0x7D:
		return "stfld", 4
	case 0x7E:
		return "ldsfld", 4
	case 0x7F:
		return "ldsflda", 4
	case 0x80:
		return "stsfld", 4
	case 0x81:
		return "stobj", 4
	case 0x82:
		return "conv.ovf.i1.un", 0
	case 0x83:
		return "conv.ovf.i2.un", 0
	case 0x84:
		return "conv.ovf.i4.un", 0
	case 0x85:
		return "conv.ovf.i8.un", 0
	case 0x86:
		return "conv.ovf.u1.un", 0
	case 0x87:
		return "conv.ovf.u2.un", 0
	case 0x88:
		return "conv.ovf.u4.un", 0
	case 0x89:
		return "conv.ovf.u8.un", 0
	case 0x8A:
		return "conv.ovf.i.un", 0
	case 0x8B:
		return "conv.ovf.u.un", 0
	case 0x8C:
		return "box", 4
	case 0x8D:
		return "newarr", 4
	case 0x8E:
		return "ldlen", 0
	case 0x8F:
		return "ldelema", 4
	case 0x90:
		return "ldelem.i1", 0
	case 0x91:
		return "ldelem.u1", 0
	case 0x92:
		return "ldelem.i2", 0
	case 0x93:
		return "ldelem.u2", 0
	case 0x94:
		return "ldelem.i4", 0
	case 0x95:
		return "ldelem.u4", 0
	case 0x96:
		return "ldelem.i8", 0
	case 0x97:
		return "ldelem.i", 0
	case 0x98:
		return "ldelem.r4", 0
	case 0x99:
		return "ldelem.r8", 0
	case 0x9A:
		return "ldelem.ref", 0
	case 0x9B:
		return "stelem.i", 0
	case 0x9C:
		return "stelem.i1", 0
	case 0x9D:
		return "stelem.i2", 0
	case 0x9E:
		return "stelem.i4", 0
	case 0x9F:
		return "stelem.i8", 0
	case 0xA0:
		return "stelem.r4", 0
	case 0xA1:
		return "stelem.r8", 0
	case 0xA2:
		return "stelem.ref", 0
	case 0xA3:
		return "ldelem", 4
	case 0xA4:
		return "stelem", 4
	case 0xA5:
		return "unbox.any", 4
	case 0xB3:
		return "conv.ovf.i1", 0
	case 0xB4:
		return "conv.ovf.u1", 0
	case 0xB5:
		return "conv.ovf.i2", 0
	case 0xB6:
		return "conv.ovf.u2", 0
	case 0xB7:
		return "conv.ovf.i4", 0
	case 0xB8:
		return "conv.ovf.u4", 0
	case 0xB9:
		return "conv.ovf.i8", 0
	case 0xBA:
		return "conv.ovf.u8", 0
	case 0xC2:
		return "refanyval", 4
	case 0xC3:
		return "ckfinite", 0
	case 0xC6:
		return "mkrefany", 4
	case 0xD0:
		return "ldtoken", 4
	case 0xD1:
		return "conv.u2", 0
	case 0xD2:
		return "conv.u1", 0
	case 0xD3:
		return "conv.i", 0
	case 0xD4:
		return "conv.ovf.i", 0
	case 0xD5:
		return "conv.ovf.u", 0
	case 0xD6:
		return "add.ovf", 0
	case 0xD7:
		return "add.ovf.un", 0
	case 0xD8:
		return "mul.ovf", 0
	case 0xD9:
		return "mul.ovf.un", 0
	case 0xDA:
		return "sub.ovf", 0
	case 0xDB:
		return "sub.ovf.un", 0
	case 0xDC:
		return "endfinally", 0
	case 0xDD:
		return "leave", 4
	case 0xDE:
		return "leave.s", 1
	case 0xDF:
		return "stind.i", 0
	case 0xE0:
		return "conv.u", 0
	}
	return "", 0
}

// ilTwoByteOp returns mnemonic and operand size for 0xFE-prefixed opcodes.
func ilTwoByteOp(op byte) (string, int) {
	switch op {
	case 0x01:
		return "ceq", 0
	case 0x02:
		return "cgt", 0
	case 0x03:
		return "cgt.un", 0
	case 0x04:
		return "clt", 0
	case 0x05:
		return "clt.un", 0
	case 0x06:
		return "ldftn", 4
	case 0x07:
		return "ldvirtftn", 4
	case 0x09:
		return "ldarg", 2
	case 0x0A:
		return "ldarga", 2
	case 0x0B:
		return "starg", 2
	case 0x0C:
		return "ldloc", 2
	case 0x0D:
		return "ldloca", 2
	case 0x0E:
		return "stloc", 2
	case 0x0F:
		return "localloc", 0
	case 0x11:
		return "endfilter", 0
	case 0x12:
		return "unaligned.", 1
	case 0x13:
		return "volatile.", 0
	case 0x14:
		return "tail.", 0
	case 0x15:
		return "initobj", 4
	case 0x16:
		return "constrained.", 4
	case 0x17:
		return "cpblk", 0
	case 0x18:
		return "initblk", 0
	case 0x19:
		return "no.", 1
	case 0x1A:
		return "rethrow", 0
	case 0x1C:
		return "sizeof", 4
	case 0x1D:
		return "refanytype", 0
	case 0x1E:
		return "readonly.", 0
	}
	return "", 0
}
