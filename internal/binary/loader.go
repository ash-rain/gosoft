package binary

import (
	"debug/pe"
	"fmt"
	"io"
	"os"
)

// Format represents the binary file format.
type Format string

const (
	FormatELF     Format = "ELF"
	FormatPE      Format = "PE"
	FormatMachO   Format = "MachO"
	FormatWASM    Format = "WASM"
	FormatUnknown Format = "Unknown"
)

// Arch represents the CPU architecture.
type Arch string

const (
	ArchX86     Arch = "x86"
	ArchX8664   Arch = "x86_64"
	ArchARM     Arch = "arm"
	ArchARM64   Arch = "arm64"
	ArchMIPS    Arch = "mips"
	ArchUnknown Arch = "unknown"
)

// Binary holds all information extracted from a binary file.
type Binary struct {
	Path     string
	Format   Format
	Arch     Arch
	Bits     int    // 32 or 64
	OS       string // "linux", "windows", "darwin", etc.
	Sections []Section
	Symbols  []Symbol
	Imports  []Import
	Strings  []StringRef
}

// Section represents a binary section/segment.
type Section struct {
	Name   string
	Offset uint64
	Size   uint64
	Data   []byte
	Flags  string
}

// Symbol represents a symbol in the binary.
type Symbol struct {
	Name    string
	Address uint64
	Size    uint64
	Type    string // "func", "object", "unknown"
}

// Import represents an imported library function.
type Import struct {
	Library string
	Name    string
	Address uint64
}

// StringRef represents a string embedded in the binary.
type StringRef struct {
	Value   string
	Offset  uint64
	Section string
}

// Load auto-detects the binary format and loads it.
func Load(path string) (*Binary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening binary %q: %w", path, err)
	}
	defer f.Close()

	format := DetectFormat(f)

	switch format {
	case FormatELF:
		return loadELF(path)
	case FormatPE:
		// Check if it's a .NET/Mono assembly before loading as plain PE
		pef, peErr := pe.Open(path)
		if peErr == nil {
			isDotNet := isDotNetPE(pef)
			pef.Close()
			if isDotNet {
				return loadDotNet(path)
			}
		}
		return loadPE(path)
	case FormatMachO:
		return loadMachO(path)
	default:
		return nil, fmt.Errorf("unsupported binary format %q for file %q", format, path)
	}
}

// DetectFormat reads the magic bytes to determine binary format.
func DetectFormat(r io.ReaderAt) Format {
	magic := make([]byte, 4)
	n, err := r.ReadAt(magic, 0)
	if err != nil || n < 2 {
		return FormatUnknown
	}

	// ELF: \x7fELF
	if n >= 4 && magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F' {
		return FormatELF
	}

	// PE: MZ
	if magic[0] == 'M' && magic[1] == 'Z' {
		return FormatPE
	}

	// WASM: \x00asm
	if n >= 4 && magic[0] == 0x00 && magic[1] == 'a' && magic[2] == 's' && magic[3] == 'm' {
		return FormatWASM
	}

	// Mach-O magic numbers
	if n >= 4 {
		// Big-endian Mach-O: \xfe\xed\xfa\xce (32-bit) or \xfe\xed\xfa\xcf (64-bit)
		if magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa &&
			(magic[3] == 0xce || magic[3] == 0xcf) {
			return FormatMachO
		}
		// Little-endian Mach-O: \xce\xfa\xed\xfe (32-bit) or \xcf\xfa\xed\xfe (64-bit)
		if (magic[0] == 0xce || magic[0] == 0xcf) && magic[1] == 0xfa &&
			magic[2] == 0xed && magic[3] == 0xfe {
			return FormatMachO
		}
		// Fat (Universal) Mach-O: \xca\xfe\xba\xbe
		if magic[0] == 0xca && magic[1] == 0xfe && magic[2] == 0xba && magic[3] == 0xbe {
			return FormatMachO
		}
	}

	return FormatUnknown
}

// extractStrings scans byte data for printable ASCII runs of 4+ characters.
func extractStrings(data []byte, sectionName string, baseOffset uint64) []StringRef {
	var result []StringRef
	const minLen = 4

	start := -1
	for i, b := range data {
		isPrintable := b >= 0x20 && b <= 0x7e
		if isPrintable {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 {
				length := i - start
				if length >= minLen {
					result = append(result, StringRef{
						Value:   string(data[start:i]),
						Offset:  baseOffset + uint64(start),
						Section: sectionName,
					})
				}
				start = -1
			}
		}
	}
	// Handle string at end of data
	if start >= 0 {
		length := len(data) - start
		if length >= minLen {
			result = append(result, StringRef{
				Value:   string(data[start:]),
				Offset:  baseOffset + uint64(start),
				Section: sectionName,
			})
		}
	}

	return result
}
