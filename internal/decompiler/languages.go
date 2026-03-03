package decompiler

import "fmt"

// SupportedLanguages returns the list of supported target language names.
func SupportedLanguages() []string {
	return []string{"go", "c", "rust", "python", "typescript", "java", "csharp"}
}

// LangDisplayName returns the human-readable name for a language key.
func LangDisplayName(lang string) string {
	switch lang {
	case "go":
		return "Go"
	case "c":
		return "C"
	case "rust":
		return "Rust"
	case "python":
		return "Python"
	case "typescript":
		return "TypeScript"
	case "java":
		return "Java"
	case "csharp":
		return "C#"
	default:
		return lang
	}
}

// LangExtension returns the file extension for a target language.
func LangExtension(lang string) string {
	switch lang {
	case "go":
		return ".go"
	case "c":
		return ".c"
	case "rust":
		return ".rs"
	case "python":
		return ".py"
	case "typescript":
		return ".ts"
	case "java":
		return ".java"
	case "csharp":
		return ".cs"
	default:
		return ".txt"
	}
}

// SystemPrompt returns the system prompt for a given target language.
func SystemPrompt(lang string) string {
	display := LangDisplayName(lang)

	if lang == "csharp" {
		return `You are a .NET decompilation expert. Given CIL/MSIL IL bytecode with full metadata context (type names, method names, field references, calling convention, cross-references, string references), produce clean, idiomatic C# code that is functionally equivalent.

Rules:
- Infer parameter names and types from ldarg patterns and call targets.
- Use the calling convention hint and cross-references to determine the function signature.
- Map string references to actual string literals in the output.
- Preserve all logic and control flow. Reconstruct if/else, loops, switch from branch patterns.
- Add brief inline comments for non-obvious operations.
- Output ONLY valid C# source code, no explanations.`
	}

	return fmt.Sprintf(`You are a binary decompilation expert. Given disassembly of a function along with rich context (calling convention, cross-references, symbol table, string references, section info), produce clean, idiomatic %s code that is functionally equivalent.

Rules:
- Use the calling convention to determine the function signature (parameter registers, return value).
- Resolve call targets using the provided cross-references and symbol names.
- Map referenced strings to actual string literals.
- Reconstruct control flow: if/else, for/while loops, switch statements from compare+branch patterns.
- Name variables meaningfully based on their usage and the called functions.
- Preserve all logic. Add brief inline comments for non-obvious operations.
- Output ONLY valid %s source code, no explanations.`, display, display)
}
