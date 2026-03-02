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
		return `You are a .NET decompilation expert. Given CIL/MSIL IL bytecode with type and method names,
produce clean, idiomatic C# code that is functionally equivalent.
Preserve all logic, types, and method signatures. Add brief inline comments for non-obvious operations.
Output ONLY valid C# source code, no explanations.`
	}

	return fmt.Sprintf(`You are a binary decompilation expert. Given disassembly with symbol hints,
produce clean, idiomatic %s code that is functionally equivalent.
Preserve all logic. Add brief inline comments for non-obvious operations.
Output ONLY valid %s source code, no explanations.`, display, display)
}
