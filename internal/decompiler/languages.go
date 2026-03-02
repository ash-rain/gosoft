package decompiler

import "fmt"

// SupportedLanguages returns the list of supported target language names.
func SupportedLanguages() []string {
	return []string{"go", "c", "rust", "python", "typescript", "java"}
}

// SystemPrompt returns the system prompt for a given target language.
func SystemPrompt(lang string) string {
	langDisplay := lang
	switch lang {
	case "go":
		langDisplay = "Go"
	case "c":
		langDisplay = "C"
	case "rust":
		langDisplay = "Rust"
	case "python":
		langDisplay = "Python"
	case "typescript":
		langDisplay = "TypeScript"
	case "java":
		langDisplay = "Java"
	default:
		langDisplay = lang
	}

	return fmt.Sprintf(`You are a binary decompilation expert. Given disassembly with symbol hints,
produce clean, idiomatic %s code that is functionally equivalent.
Preserve all logic. Add brief inline comments for non-obvious operations.
Output ONLY valid %s source code, no explanations.`, langDisplay, langDisplay)
}
