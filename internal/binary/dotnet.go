package binary

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// FormatDotNet identifies .NET/Mono assemblies (PE with CLR header).
const FormatDotNet Format = "DotNet"

// dotNetAssemblyInfo holds parsed .NET metadata.
type dotNetAssemblyInfo struct {
	AssemblyName string
	Version      string
	Types        []dotNetType
}

type dotNetType struct {
	Namespace string
	Name      string
	Flags     uint32
	Methods   []dotNetMethod
}

type dotNetMethod struct {
	Name      string
	Flags     uint16
	ImplFlags uint16
	RVA       uint32
	ILBytes   []byte
}

// isDotNetPE returns true if the PE file contains a CLR header.
func isDotNetPE(f *pe.File) bool {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return oh.DataDirectory[14].VirtualAddress != 0 && oh.DataDirectory[14].Size > 0
	case *pe.OptionalHeader64:
		return oh.DataDirectory[14].VirtualAddress != 0 && oh.DataDirectory[14].Size > 0
	}
	return false
}

// loadDotNet loads a .NET/Mono assembly, parsing both PE structure and CLR metadata.
func loadDotNet(path string) (*Binary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading .NET assembly %q: %w", path, err)
	}

	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening .NET PE %q: %w", path, err)
	}
	defer f.Close()

	b := &Binary{
		Path:   path,
		Format: FormatDotNet,
		OS:     "windows",
	}

	// Determine architecture
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		b.Arch = ArchX86
		b.Bits = 32
	case pe.IMAGE_FILE_MACHINE_AMD64:
		b.Arch = ArchX8664
		b.Bits = 64
	case pe.IMAGE_FILE_MACHINE_ARM64:
		b.Arch = ArchARM64
		b.Bits = 64
	default:
		b.Arch = ArchX86 // default for MSIL/AnyCPU
		b.Bits = 32
	}

	// Load PE sections
	for _, sec := range f.Sections {
		secData, err := sec.Data()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: reading .NET section %q: %v\n", sec.Name, err)
			secData = nil
		}
		b.Sections = append(b.Sections, Section{
			Name:   sec.Name,
			Offset: uint64(sec.VirtualAddress),
			Size:   uint64(sec.Size),
			Data:   secData,
			Flags:  fmt.Sprintf("0x%x", sec.Characteristics),
		})
		if (sec.Name == ".rdata" || sec.Name == ".data") && len(secData) > 0 {
			b.Strings = append(b.Strings, extractStrings(secData, sec.Name, uint64(sec.Offset))...)
		}
	}

	// Get CLR header RVA from DataDirectory[14]
	var clrRVA, clrSize uint32
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		clrRVA = oh.DataDirectory[14].VirtualAddress
		clrSize = oh.DataDirectory[14].Size
	case *pe.OptionalHeader64:
		clrRVA = oh.DataDirectory[14].VirtualAddress
		clrSize = oh.DataDirectory[14].Size
	}

	if clrRVA == 0 || clrSize < 72 {
		return b, nil // not a .NET assembly or no metadata
	}

	// Parse CLR header
	clrFileOff, err := rvaToFileOffset(f, clrRVA)
	if err != nil || int(clrFileOff)+72 > len(data) {
		return b, nil
	}
	clrData := data[clrFileOff : clrFileOff+72]

	metaRVA := binary.LittleEndian.Uint32(clrData[8:12])
	// metaSize := binary.LittleEndian.Uint32(clrData[12:16])

	if metaRVA == 0 {
		return b, nil
	}

	// Parse metadata root
	metaFileOff, err := rvaToFileOffset(f, metaRVA)
	if err != nil || int(metaFileOff)+16 > len(data) {
		return b, nil
	}
	metaData := data[metaFileOff:]

	sig := binary.LittleEndian.Uint32(metaData[0:4])
	if sig != 0x424A5342 { // "BSJB"
		return b, nil
	}

	// Skip to version string length
	if len(metaData) < 16 {
		return b, nil
	}
	versionLen := binary.LittleEndian.Uint32(metaData[12:16])
	// Pad to 4-byte boundary
	versionLen = (versionLen + 3) &^ 3

	off := 16 + int(versionLen)
	if off+4 > len(metaData) {
		return b, nil
	}

	// flags (2 bytes) + numStreams (2 bytes)
	numStreams := binary.LittleEndian.Uint16(metaData[off+2 : off+4])
	off += 4

	// Parse stream headers
	type streamHeader struct {
		offset uint32
		size   uint32
		name   string
	}
	streams := make(map[string]streamHeader, numStreams)

	for i := 0; i < int(numStreams); i++ {
		if off+8 > len(metaData) {
			break
		}
		sh := streamHeader{
			offset: binary.LittleEndian.Uint32(metaData[off : off+4]),
			size:   binary.LittleEndian.Uint32(metaData[off+4 : off+8]),
		}
		off += 8
		// Read null-terminated name, padded to 4 bytes
		nameStart := off
		for off < len(metaData) && metaData[off] != 0 {
			off++
		}
		sh.name = string(metaData[nameStart:off])
		off++ // skip null
		off = (off + 3) &^ 3 // pad to 4
		streams[sh.name] = sh
	}

	// Get heap slices
	stringsHeap := streamSlice(metaData, streams["#Strings"])
	// userStrings := streamSlice(metaData, streams["#US"])
	// blobHeap := streamSlice(metaData, streams["#Blob"])

	// Parse #~ (compressed metadata tables)
	tablesStream, ok := streams["#~"]
	if !ok {
		tablesStream, ok = streams["#-"] // uncompressed variant
	}
	if !ok || tablesStream.size == 0 {
		return b, nil
	}
	tablesData := streamSlice(metaData, tablesStream)
	if len(tablesData) < 24 {
		return b, nil
	}

	heapSizes := tablesData[6]
	stringIndex4 := (heapSizes & 0x01) != 0
	blobIndex4 := (heapSizes & 0x04) != 0
	_ = blobIndex4

	valid := binary.LittleEndian.Uint64(tablesData[8:16])
	// sorted := binary.LittleEndian.Uint64(tablesData[16:24])

	// Read row counts
	var rowCounts [64]uint32
	rowOff := 24
	for i := 0; i < 64; i++ {
		if (valid>>uint(i))&1 == 1 {
			if rowOff+4 > len(tablesData) {
				break
			}
			rowCounts[i] = binary.LittleEndian.Uint32(tablesData[rowOff : rowOff+4])
			rowOff += 4
		}
	}

	// Compute index sizes for coded indexes
	stringIdxSize := 2
	if stringIndex4 {
		stringIdxSize = 4
	}
	blobIdxSize := 2
	if blobIndex4 {
		blobIdxSize = 4
	}

	// Coded index: TypeDefOrRef (2 bits, tables 2=TypeDef, 1=TypeRef, 27=TypeSpec)
	typeDefOrRefSize := codedIndexSize(2, rowCounts[2], rowCounts[1], rowCounts[27])

	// Simple table index sizes
	fieldIdxSize := tableIndexSize(rowCounts[4])
	methodIdxSize := tableIndexSize(rowCounts[6])
	paramIdxSize := tableIndexSize(rowCounts[8])

	// --- Parse TypeDef table (table 0x02) ---
	// Row: Flags(4) + Name(str) + Namespace(str) + Extends(coded) + FieldList(idx) + MethodList(idx)
	typeDefRowSize := 4 + stringIdxSize + stringIdxSize + typeDefOrRefSize + fieldIdxSize + methodIdxSize

	typeDefOffset := tableOffset(tablesData, rowOff, valid, rowCounts, typeDefRowSize, 2)

	type typeDefRow struct {
		flags      uint32
		name       string
		namespace  string
		methodList uint32
		methodEnd  uint32 // exclusive upper bound
	}
	typeRows := make([]typeDefRow, rowCounts[2])
	for i := 0; i < int(rowCounts[2]); i++ {
		base := typeDefOffset + i*typeDefRowSize
		if base+typeDefRowSize > len(tablesData) {
			break
		}
		row := typeDefRow{}
		p := base
		row.flags = binary.LittleEndian.Uint32(tablesData[p : p+4])
		p += 4
		row.name = readStringHeap(stringsHeap, tablesData[p:p+stringIdxSize], stringIndex4)
		p += stringIdxSize
		row.namespace = readStringHeap(stringsHeap, tablesData[p:p+stringIdxSize], stringIndex4)
		p += stringIdxSize
		p += typeDefOrRefSize // skip Extends
		p += fieldIdxSize     // skip FieldList
		row.methodList = readTableIndex(tablesData[p:p+methodIdxSize], methodIdxSize)
		typeRows[i] = row
	}
	// Fill in methodEnd (next type's methodList, or total+1 for last)
	for i := range typeRows {
		if i+1 < len(typeRows) {
			typeRows[i].methodEnd = typeRows[i+1].methodList
		} else {
			typeRows[i].methodEnd = rowCounts[6] + 1
		}
	}

	// --- Parse MethodDef table (table 0x06) ---
	// Row: RVA(4) + ImplFlags(2) + Flags(2) + Name(str) + Signature(blob) + ParamList(idx)
	methodDefRowSize := 4 + 2 + 2 + stringIdxSize + blobIdxSize + paramIdxSize

	methodDefOffset := tableOffset(tablesData, rowOff, valid, rowCounts, methodDefRowSize, 6)

	type methodDefRow struct {
		rva       uint32
		implFlags uint16
		flags     uint16
		name      string
	}
	methodRows := make([]methodDefRow, rowCounts[6])
	for i := 0; i < int(rowCounts[6]); i++ {
		base := methodDefOffset + i*methodDefRowSize
		if base+methodDefRowSize > len(tablesData) {
			break
		}
		row := methodDefRow{}
		p := base
		row.rva = binary.LittleEndian.Uint32(tablesData[p : p+4])
		p += 4
		row.implFlags = binary.LittleEndian.Uint16(tablesData[p : p+2])
		p += 2
		row.flags = binary.LittleEndian.Uint16(tablesData[p : p+2])
		p += 2
		row.name = readStringHeap(stringsHeap, tablesData[p:p+stringIdxSize], stringIndex4)
		methodRows[i] = row
	}

	// Build symbols: "Namespace.TypeName::MethodName" for each method
	for _, tr := range typeRows {
		if tr.name == "" || tr.name == "<Module>" {
			continue
		}
		typeFQN := tr.name
		if tr.namespace != "" {
			typeFQN = tr.namespace + "." + tr.name
		}

		for mi := tr.methodList; mi < tr.methodEnd && mi > 0; mi++ {
			idx := int(mi) - 1 // 1-based index
			if idx < 0 || idx >= len(methodRows) {
				break
			}
			mr := methodRows[idx]
			if mr.name == "" {
				continue
			}

			symName := typeFQN + "::" + mr.name
			symAddr := uint64(mr.rva)

			b.Symbols = append(b.Symbols, Symbol{
				Name:    symName,
				Address: symAddr,
				Size:    0,
				Type:    "func",
			})

			// Extract IL bytes for this method if RVA is valid
			if mr.rva != 0 {
				ilBytes := extractILBody(data, f, mr.rva)
				if len(ilBytes) > 0 {
					sectionName := "IL:" + symName
					b.Sections = append(b.Sections, Section{
						Name:   sectionName,
						Offset: symAddr,
						Size:   uint64(len(ilBytes)),
						Data:   ilBytes,
						Flags:  "il",
					})
				}
			}
		}
	}

	// Extract user strings from #US heap
	usStream, hasUS := streams["#US"]
	if hasUS && usStream.size > 0 {
		usData := streamSlice(metaData, usStream)
		extractUSStrings(b, usData)
	}

	// Try to get assembly name from Assembly table (0x20)
	if rowCounts[0x20] > 0 {
		// We already have the binary name from path
		b.OS = detectDotNetOS(b)
	}

	return b, nil
}

// extractILBody extracts the IL byte code for a method at the given RVA.
func extractILBody(data []byte, f *pe.File, rva uint32) []byte {
	fileOff, err := rvaToFileOffset(f, rva)
	if err != nil || int(fileOff) >= len(data) {
		return nil
	}
	header := data[fileOff]
	headerType := header & 0x03

	switch headerType {
	case 0x02: // Tiny format: upper 6 bits = code size
		codeSize := int(header >> 2)
		start := int(fileOff) + 1
		if start+codeSize > len(data) {
			codeSize = len(data) - start
		}
		if codeSize <= 0 {
			return nil
		}
		out := make([]byte, codeSize)
		copy(out, data[start:start+codeSize])
		return out

	case 0x03: // Fat format: 12-byte header
		if int(fileOff)+12 > len(data) {
			return nil
		}
		// Flags and header size are packed into first 2 bytes
		// fat header size in dwords = flags>>12 (should be 3 = 12 bytes)
		codeSize := int(binary.LittleEndian.Uint32(data[fileOff+4 : fileOff+8]))
		start := int(fileOff) + 12
		if start+codeSize > len(data) {
			codeSize = len(data) - start
		}
		if codeSize <= 0 {
			return nil
		}
		out := make([]byte, codeSize)
		copy(out, data[start:start+codeSize])
		return out
	}
	return nil
}

// extractUSStrings parses user string blobs from the #US heap and adds them to the binary.
func extractUSStrings(b *Binary, usData []byte) {
	off := 1 // skip leading zero byte
	for off < len(usData) {
		if off >= len(usData) {
			break
		}
		// Read blob length (compressed unsigned int)
		blobLen, n := readCompressedUint(usData[off:])
		off += n
		if blobLen == 0 || off+int(blobLen) > len(usData) {
			off += int(blobLen)
			continue
		}
		// User strings are UTF-16LE with a terminal byte
		strBytes := usData[off : off+int(blobLen)-1]
		off += int(blobLen)

		// Convert UTF-16LE to string
		var sb strings.Builder
		for i := 0; i+1 < len(strBytes); i += 2 {
			ch := uint16(strBytes[i]) | uint16(strBytes[i+1])<<8
			if ch >= 0x20 && ch < 0x7f {
				sb.WriteByte(byte(ch))
			} else if ch == 0 {
				break
			}
		}
		s := sb.String()
		if len(s) >= 4 {
			b.Strings = append(b.Strings, StringRef{
				Value:   s,
				Offset:  0,
				Section: "#US",
			})
		}
	}
}

// detectDotNetOS tries to determine the target OS from assembly attributes.
func detectDotNetOS(b *Binary) string {
	// Check if it's a Mono assembly (Linux/macOS)
	for _, imp := range b.Imports {
		if strings.Contains(strings.ToLower(imp.Library), "mono") {
			return "linux"
		}
	}
	return "windows"
}

// --- Metadata parsing helpers ---

func rvaToFileOffset(f *pe.File, rva uint32) (uint32, error) {
	for _, sec := range f.Sections {
		if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+sec.Size {
			return sec.Offset + (rva - sec.VirtualAddress), nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%08x not in any section", rva)
}

func streamSlice(meta []byte, sh struct {
	offset uint32
	size   uint32
	name   string
}) []byte {
	start := int(sh.offset)
	end := start + int(sh.size)
	if start >= len(meta) || end > len(meta) || start >= end {
		return nil
	}
	return meta[start:end]
}

func readStringHeap(heap, idxBytes []byte, use4 bool) string {
	if len(idxBytes) == 0 || len(heap) == 0 {
		return ""
	}
	var idx uint32
	if use4 && len(idxBytes) >= 4 {
		idx = binary.LittleEndian.Uint32(idxBytes[:4])
	} else if len(idxBytes) >= 2 {
		idx = uint32(binary.LittleEndian.Uint16(idxBytes[:2]))
	}
	if int(idx) >= len(heap) {
		return ""
	}
	end := int(idx)
	for end < len(heap) && heap[end] != 0 {
		end++
	}
	return string(heap[idx:end])
}

func readTableIndex(data []byte, size int) uint32 {
	if size == 4 && len(data) >= 4 {
		return binary.LittleEndian.Uint32(data[:4])
	}
	if len(data) >= 2 {
		return uint32(binary.LittleEndian.Uint16(data[:2]))
	}
	return 0
}

func tableIndexSize(rows uint32) int {
	if rows > 65535 {
		return 4
	}
	return 2
}

func codedIndexSize(tagBits int, rowCounts ...uint32) int {
	maxRows := uint32(0)
	for _, r := range rowCounts {
		if r > maxRows {
			maxRows = r
		}
	}
	threshold := uint32(1) << (16 - uint(tagBits))
	if maxRows >= threshold {
		return 4
	}
	return 2
}

// tableOffset computes the byte offset of table `tableID` within tablesData,
// starting after the row count array at rowCountsEnd.
func tableOffset(tablesData []byte, rowCountsEnd int, valid uint64, rowCounts [64]uint32, rowSizeForTarget int, targetTableID int) int {
	off := rowCountsEnd

	// We need to compute row sizes for all tables that appear before targetTableID
	// For simplicity, we'll use estimated row sizes for tables we don't care about
	// Order tables by their table ID
	for id := 0; id < targetTableID; id++ {
		if (valid>>uint(id))&1 == 0 {
			continue
		}
		size := estimateRowSize(id)
		off += int(rowCounts[id]) * size
	}
	return off
}

// estimateRowSize returns the estimated row size for a metadata table.
// This is an approximation using 2-byte indices (small assemblies).
func estimateRowSize(tableID int) int {
	// Row sizes for common tables with 2-byte indices
	switch tableID {
	case 0x00: // Module: Generation(2)+Name(2)+Mvid(2)+EncId(2)+EncBaseId(2)
		return 10
	case 0x01: // TypeRef: ResolutionScope(2)+Name(2)+Namespace(2)
		return 6
	case 0x02: // TypeDef: Flags(4)+Name(2)+Namespace(2)+Extends(2)+FieldList(2)+MethodList(2)
		return 14
	case 0x04: // Field: Flags(2)+Name(2)+Signature(2)
		return 6
	case 0x06: // MethodDef: RVA(4)+ImplFlags(2)+Flags(2)+Name(2)+Signature(2)+ParamList(2)
		return 14
	case 0x08: // Param: Flags(2)+Sequence(2)+Name(2)
		return 6
	case 0x09: // InterfaceImpl: Class(2)+Interface(2)
		return 4
	case 0x0A: // MemberRef: Class(2)+Name(2)+Signature(2)
		return 6
	case 0x0B: // Constant: Type(2)+Parent(2)+Value(2)
		return 6
	case 0x0C: // CustomAttribute: Parent(2)+Type(2)+Value(2)
		return 6
	case 0x0D: // FieldMarshal: Parent(2)+NativeType(2)
		return 4
	case 0x0E: // DeclSecurity: Action(2)+Parent(2)+PermissionSet(2)
		return 6
	case 0x0F: // ClassLayout: PackingSize(2)+ClassSize(4)+Parent(2)
		return 8
	case 0x10: // FieldLayout: Offset(4)+Field(2)
		return 6
	case 0x11: // StandAloneSig: Signature(2)
		return 2
	case 0x12: // EventMap: Parent(2)+EventList(2)
		return 4
	case 0x14: // Event: EventFlags(2)+Name(2)+EventType(2)
		return 6
	case 0x15: // PropertyMap: Parent(2)+PropertyList(2)
		return 4
	case 0x17: // Property: Flags(2)+Name(2)+Type(2)
		return 6
	case 0x18: // MethodSemantics: Semantics(2)+Method(2)+Association(2)
		return 6
	case 0x19: // MethodImpl: Class(2)+MethodBody(2)+MethodDeclaration(2)
		return 6
	case 0x1A: // ModuleRef: Name(2)
		return 2
	case 0x1B: // TypeSpec: Signature(2)
		return 2
	case 0x1C: // ImplMap: MappingFlags(2)+MemberForwarded(2)+ImportName(2)+ImportScope(2)
		return 8
	case 0x1D: // FieldRVA: RVA(4)+Field(2)
		return 6
	case 0x20: // Assembly: various ~20 bytes
		return 22
	case 0x21: // AssemblyProcessor: Processor(4)
		return 4
	case 0x22: // AssemblyOS: OSPlatformId(4)+OSMajorVersion(4)+OSMinorVersion(4)
		return 12
	case 0x23: // AssemblyRef: ~20 bytes
		return 20
	case 0x24: // AssemblyRefProcessor: Processor(4)+AssemblyRef(2)
		return 6
	case 0x25: // AssemblyRefOS: ~14 bytes
		return 14
	case 0x26: // File: Flags(4)+Name(2)+HashValue(2)
		return 8
	case 0x27: // ExportedType: Flags(4)+TypeDefId(4)+TypeName(2)+TypeNamespace(2)+Implementation(2)
		return 14
	case 0x28: // ManifestResource: Offset(4)+Flags(4)+Name(2)+Implementation(2)
		return 12
	case 0x29: // NestedClass: NestedClass(2)+EnclosingClass(2)
		return 4
	case 0x2A: // GenericParam: Number(2)+Flags(2)+Owner(2)+Name(2)
		return 8
	case 0x2B: // MethodSpec: Method(2)+Instantiation(2)
		return 4
	case 0x2C: // GenericParamConstraint: Owner(2)+Constraint(2)
		return 4
	default:
		return 6 // conservative estimate
	}
}

// readCompressedUint reads a ECMA-335 compressed unsigned integer.
func readCompressedUint(data []byte) (uint32, int) {
	if len(data) == 0 {
		return 0, 0
	}
	b0 := data[0]
	if b0&0x80 == 0 {
		return uint32(b0), 1
	}
	if b0&0xC0 == 0x80 && len(data) >= 2 {
		return uint32(b0&0x3F)<<8 | uint32(data[1]), 2
	}
	if b0&0xE0 == 0xC0 && len(data) >= 4 {
		return uint32(b0&0x1F)<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]), 4
	}
	return 0, 1
}
