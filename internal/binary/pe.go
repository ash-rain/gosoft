package binary

import (
	"debug/pe"
	"fmt"
	"os"
)

func loadPE(path string) (*Binary, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening PE %q: %w", path, err)
	}
	defer f.Close()

	b := &Binary{
		Path:   path,
		Format: FormatPE,
		OS:     "windows",
	}

	// Determine architecture from Machine field
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		b.Arch = ArchX86
		b.Bits = 32
	case pe.IMAGE_FILE_MACHINE_AMD64:
		b.Arch = ArchX8664
		b.Bits = 64
	case pe.IMAGE_FILE_MACHINE_ARM:
		b.Arch = ArchARM
		b.Bits = 32
	case pe.IMAGE_FILE_MACHINE_ARM64:
		b.Arch = ArchARM64
		b.Bits = 64
	default:
		b.Arch = ArchUnknown
		b.Bits = 32
	}

	// Load sections
	for _, sec := range f.Sections {
		data, err := sec.Data()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: reading PE section %q data: %v\n", sec.Name, err)
			data = nil
		}

		s := Section{
			Name:   sec.Name,
			Offset: uint64(sec.Offset),
			Size:   uint64(sec.Size),
			Data:   data,
			Flags:  fmt.Sprintf("0x%x", sec.Characteristics),
		}
		b.Sections = append(b.Sections, s)

		// Extract strings from .rdata and .data sections
		if (sec.Name == ".rdata" || sec.Name == ".data") && len(data) > 0 {
			refs := extractStrings(data, sec.Name, uint64(sec.Offset))
			b.Strings = append(b.Strings, refs...)
		}
	}

	// Load symbols
	for _, sym := range f.Symbols {
		symType := "unknown"
		// PE symbol type: 0x20 = function
		if sym.Type == 0x20 {
			symType = "func"
		}
		if sym.Name == "" {
			continue
		}
		b.Symbols = append(b.Symbols, Symbol{
			Name:    sym.Name,
			Address: uint64(sym.Value),
			Size:    0, // PE symbols don't have size directly
			Type:    symType,
		})
	}

	// Load imported symbols
	importedSyms, err := f.ImportedSymbols()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: loading PE imported symbols: %v\n", err)
	} else {
		for _, sym := range importedSyms {
			b.Imports = append(b.Imports, Import{
				Library: sym,
				Name:    sym,
				Address: 0,
			})
		}
	}

	// Load imported libraries
	libs, err := f.ImportedLibraries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: loading PE imported libraries: %v\n", err)
	}

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
