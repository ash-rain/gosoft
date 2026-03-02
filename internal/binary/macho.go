package binary

import (
	"debug/macho"
	"fmt"
	"os"
)

func loadMachO(path string) (*Binary, error) {
	f, err := macho.Open(path)
	if err != nil {
		// Try opening as a fat binary
		fat, fatErr := macho.OpenFat(path)
		if fatErr != nil {
			return nil, fmt.Errorf("opening Mach-O %q: %w", path, err)
		}
		defer fat.Close()
		if len(fat.Arches) == 0 {
			return nil, fmt.Errorf("fat binary %q has no architectures", path)
		}
		// Use the first architecture
		return loadMachOFile(path, fat.Arches[0].File)
	}
	defer f.Close()
	return loadMachOFile(path, f)
}

func loadMachOFile(path string, f *macho.File) (*Binary, error) {
	b := &Binary{
		Path:   path,
		Format: FormatMachO,
		OS:     "darwin",
	}

	// Determine architecture
	switch f.Cpu {
	case macho.CpuAmd64:
		b.Arch = ArchX8664
		b.Bits = 64
	case macho.Cpu386:
		b.Arch = ArchX86
		b.Bits = 32
	case macho.CpuArm:
		b.Arch = ArchARM
		b.Bits = 32
	case macho.CpuArm64:
		b.Arch = ArchARM64
		b.Bits = 64
	default:
		b.Arch = ArchUnknown
		b.Bits = 64
	}

	// Load sections
	for _, sec := range f.Sections {
		data, err := sec.Data()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: reading Mach-O section %q data: %v\n", sec.Name, err)
			data = nil
		}

		s := Section{
			Name:   sec.Name,
			Offset: uint64(sec.Offset),
			Size:   sec.Size,
			Data:   data,
			Flags:  fmt.Sprintf("0x%x", sec.Flags),
		}
		b.Sections = append(b.Sections, s)

		// Extract strings from __cstring, __data sections
		if (sec.Name == "__cstring" || sec.Name == "__const" || sec.Name == "__data") && len(data) > 0 {
			refs := extractStrings(data, sec.Name, uint64(sec.Offset))
			b.Strings = append(b.Strings, refs...)
		}
	}

	// Load symbols
	if f.Symtab != nil {
		for _, sym := range f.Symtab.Syms {
			symType := "unknown"
			// Mach-O N_TYPE field: 0xe = N_SECT (defined in a section)
			// Mach-O type flags: 0x0f = N_TYPE mask
			ntype := sym.Type & 0x0f
			if ntype == 0x0e { // N_SECT - regular symbol
				symType = "func"
			}
			if sym.Name == "" {
				continue
			}
			b.Symbols = append(b.Symbols, Symbol{
				Name:    sym.Name,
				Address: sym.Value,
				Size:    0, // Mach-O symtab doesn't have size directly
				Type:    symType,
			})
		}
	}

	// Load imported libraries
	libs, err := f.ImportedLibraries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: loading Mach-O imported libraries: %v\n", err)
	}

	// Load imported symbols (returns []string in format "name$INODE$library")
	importedSyms, err := f.ImportedSymbols()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: loading Mach-O imported symbols: %v\n", err)
	} else {
		for _, symStr := range importedSyms {
			b.Imports = append(b.Imports, Import{
				Library: "",
				Name:    symStr,
				Address: 0,
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
