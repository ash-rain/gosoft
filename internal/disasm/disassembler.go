package disasm

import "fmt"

// Instruction represents one disassembled instruction.
type Instruction struct {
	Address  uint64
	Bytes    []byte
	Mnemonic string
	OpStr    string
	Comment  string
}

// Disassembler is the interface for architecture-specific disassemblers.
type Disassembler interface {
	Disassemble(data []byte, startAddr uint64) ([]Instruction, error)
	Arch() string
}

// errUnsupportedArch is returned when no disassembler is available for the arch.
type errUnsupportedArch struct {
	arch string
}

func (e *errUnsupportedArch) Error() string {
	return fmt.Sprintf("unsupported architecture: %s", e.arch)
}

// New returns the right disassembler for the given arch string.
func New(arch string) (Disassembler, error) {
	switch arch {
	case "x86":
		return &x86Disasm{bits: 32}, nil
	case "x86_64":
		return &x86Disasm{bits: 64}, nil
	case "arm":
		return &armDisasm{bits: 32}, nil
	case "arm64":
		return &armDisasm{bits: 64}, nil
	default:
		return nil, &errUnsupportedArch{arch: arch}
	}
}
