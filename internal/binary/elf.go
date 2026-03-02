package binary

import (
	"debug/elf"
	"fmt"
	"os"
)

func loadELF(path string) (*Binary, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening ELF %q: %w", path, err)
	}
	defer f.Close()

	b := &Binary{
		Path:   path,
		Format: FormatELF,
	}

	// Determine architecture
	switch f.Machine {
	case elf.EM_386:
		b.Arch = ArchX86
		b.Bits = 32
	case elf.EM_X86_64:
		b.Arch = ArchX8664
		b.Bits = 64
	case elf.EM_ARM:
		b.Arch = ArchARM
		b.Bits = 32
	case elf.EM_AARCH64:
		b.Arch = ArchARM64
		b.Bits = 64
	case elf.EM_MIPS:
		b.Arch = ArchMIPS
		b.Bits = 32
	default:
		b.Arch = ArchUnknown
		if f.Class == elf.ELFCLASS64 {
			b.Bits = 64
		} else {
			b.Bits = 32
		}
	}

	// Determine OS from OSABI
	switch f.OSABI {
	case elf.ELFOSABI_LINUX:
		b.OS = "linux"
	case elf.ELFOSABI_FREEBSD:
		b.OS = "freebsd"
	case elf.ELFOSABI_NETBSD:
		b.OS = "netbsd"
	case elf.ELFOSABI_OPENBSD:
		b.OS = "openbsd"
	default:
		b.OS = "linux" // default assumption for ELF
	}

	// Load sections
	for _, sec := range f.Sections {
		if sec.Type == elf.SHT_NULL {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			// Log but continue - some sections may not be readable
			fmt.Fprintf(os.Stderr, "warning: reading section %q data: %v\n", sec.Name, err)
			data = nil
		}
		s := Section{
			Name:   sec.Name,
			Offset: sec.Offset,
			Size:   sec.Size,
			Data:   data,
			Flags:  fmt.Sprintf("%v", sec.Flags),
		}
		b.Sections = append(b.Sections, s)

		// Extract strings from relevant sections
		if (sec.Name == ".rodata" || sec.Name == ".data" || sec.Name == ".data.rel.ro") && len(data) > 0 {
			refs := extractStrings(data, sec.Name, sec.Offset)
			b.Strings = append(b.Strings, refs...)
		}
	}

	// Load symbols
	syms, err := f.Symbols()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: loading ELF symbols: %v\n", err)
	} else {
		for _, sym := range syms {
			symType := "unknown"
			switch elf.ST_TYPE(sym.Info) {
			case elf.STT_FUNC:
				symType = "func"
			case elf.STT_OBJECT:
				symType = "object"
			}
			if sym.Name == "" {
				continue
			}
			b.Symbols = append(b.Symbols, Symbol{
				Name:    sym.Name,
				Address: sym.Value,
				Size:    sym.Size,
				Type:    symType,
			})
		}
	}

	// Load dynamic symbols
	dynSyms, err := f.DynamicSymbols()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: loading ELF dynamic symbols: %v\n", err)
	} else {
		for _, sym := range dynSyms {
			symType := "unknown"
			switch elf.ST_TYPE(sym.Info) {
			case elf.STT_FUNC:
				symType = "func"
			case elf.STT_OBJECT:
				symType = "object"
			}
			if sym.Name == "" {
				continue
			}
			b.Symbols = append(b.Symbols, Symbol{
				Name:    sym.Name,
				Address: sym.Value,
				Size:    sym.Size,
				Type:    symType,
			})
		}
	}

	// Load imported libraries
	libs, err := f.ImportedLibraries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: loading ELF imported libraries: %v\n", err)
	}

	// Load imported symbols
	importedSyms, err := f.ImportedSymbols()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: loading ELF imported symbols: %v\n", err)
	} else {
		for _, sym := range importedSyms {
			b.Imports = append(b.Imports, Import{
				Library: sym.Library,
				Name:    sym.Name,
				Address: 0, // not directly available
			})
		}
	}

	// Add libraries without specific symbols
	libSet := make(map[string]bool)
	for _, imp := range b.Imports {
		libSet[imp.Library] = true
	}
	for _, lib := range libs {
		if !libSet[lib] {
			b.Imports = append(b.Imports, Import{
				Library: lib,
				Name:    "",
				Address: 0,
			})
		}
	}

	return b, nil
}
