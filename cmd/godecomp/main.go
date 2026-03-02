package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"godecomp/internal/ai"
	"godecomp/internal/binary"
	"godecomp/internal/decompiler"
	"godecomp/internal/symbols"
	"godecomp/pkg/godecomp"
)

var (
	ollamaURL   string
	model       string
	opencodeURL string
	opencodeKey string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "godecomp",
		Short: "AI-powered binary decompiler",
		Long: `GoDecomp is an AI-powered binary decompiler that supports multiple
architectures and can decompile to any target language using local Ollama
models or free cloud AI providers.`,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&ollamaURL, "ollama-url", "http://localhost:11434",
		"Ollama API URL")
	rootCmd.PersistentFlags().StringVar(&model, "model", "deepseek-coder:latest",
		"AI model to use")
	rootCmd.PersistentFlags().StringVar(&opencodeURL, "opencode-url", "",
		"OpenCode-compatible API URL (optional)")
	rootCmd.PersistentFlags().StringVar(&opencodeKey, "opencode-key", "",
		"OpenCode API key (optional)")

	// Bind to viper
	viper.BindPFlag("ollama_url", rootCmd.PersistentFlags().Lookup("ollama-url"))
	viper.BindPFlag("model", rootCmd.PersistentFlags().Lookup("model"))

	// Add subcommands
	rootCmd.AddCommand(
		newDecompileCmd(),
		newExploreCmd(),
		newSymbolsCmd(),
		newStringsCmd(),
		newAskCmd(),
		newModelsCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// newDecompileCmd creates the "decompile" subcommand.
func newDecompileCmd() *cobra.Command {
	var (
		funcName  string
		lang      string
		all       bool
		outDir    string
		streamOut bool
	)

	cmd := &cobra.Command{
		Use:   "decompile <binary>",
		Short: "Decompile a binary or specific function",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			binaryPath := args[0]

			cfg := godecomp.Config{
				OllamaURL:      ollamaURL,
				OllamaModel:    model,
				OpenCodeURL:    opencodeURL,
				OpenCodeAPIKey: opencodeKey,
				DefaultLang:    lang,
			}

			session, err := godecomp.Open(binaryPath, cfg)
			if err != nil {
				return fmt.Errorf("opening binary: %w", err)
			}

			if lang == "" {
				lang = "go"
			}

			// If no function specified, list functions and prompt
			if funcName == "" && !all {
				funcs := session.Symbols()
				if len(funcs) == 0 {
					return fmt.Errorf("no function symbols found in %s", binaryPath)
				}
				fmt.Printf("Available functions in %s:\n\n", binaryPath)
				for i, sym := range funcs {
					fmt.Printf("  %3d. %-40s  0x%x\n", i+1, sym.Name, sym.Address)
					if i >= 49 {
						fmt.Printf("  ... and %d more\n", len(funcs)-50)
						break
					}
				}
				fmt.Printf("\nUse --func <name> to decompile a specific function.\n")
				return nil
			}

			ctx := context.Background()

			if all {
				// Decompile all functions
				funcs := session.Symbols()
				if len(funcs) == 0 {
					return fmt.Errorf("no function symbols found in %s", binaryPath)
				}

				if outDir != "" {
					if err := os.MkdirAll(outDir, 0755); err != nil {
						return fmt.Errorf("creating output directory: %w", err)
					}
				}

				for _, sym := range funcs {
					fmt.Fprintf(os.Stderr, "Decompiling %s...\n", sym.Name)
					result, err := session.Decompile(ctx, sym.Name, lang)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error decompiling %s: %v\n", sym.Name, err)
						continue
					}

					if outDir != "" {
						filename := strings.ReplaceAll(sym.Name, "/", "_")
						ext := langExtension(lang)
						outPath := fmt.Sprintf("%s/%s%s", outDir, filename, ext)
						if err := os.WriteFile(outPath, []byte(result), 0644); err != nil {
							fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", outPath, err)
						}
					} else {
						fmt.Printf("// Function: %s\n%s\n\n", sym.Name, result)
					}
				}
				return nil
			}

			// Decompile single function
			if streamOut {
				ch := make(chan ai.StreamChunk, 100)
				if err := session.DecompileStream(ctx, funcName, lang, ch); err != nil {
					return fmt.Errorf("starting stream: %w", err)
				}
				for chunk := range ch {
					if chunk.Error != nil {
						return fmt.Errorf("stream error: %w", chunk.Error)
					}
					if chunk.Done {
						break
					}
					fmt.Print(chunk.Text)
				}
				fmt.Println()
			} else {
				result, err := session.Decompile(ctx, funcName, lang)
				if err != nil {
					return fmt.Errorf("decompiling %s: %w", funcName, err)
				}
				fmt.Println(result)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&funcName, "func", "f", "", "Function name to decompile")
	cmd.Flags().StringVarP(&lang, "lang", "l", "go", "Target language (go, c, rust, python, typescript, java)")
	cmd.Flags().BoolVarP(&all, "all", "a", false, "Decompile all functions")
	cmd.Flags().StringVarP(&outDir, "out", "o", "", "Output directory (for --all)")
	cmd.Flags().BoolVarP(&streamOut, "stream", "s", false, "Stream output tokens")

	return cmd
}

// newExploreCmd creates the "explore" subcommand.
func newExploreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explore <binary>",
		Short: "Explore binary in interactive TUI",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			binaryPath := args[0]

			cfg := godecomp.Config{
				OllamaURL:      ollamaURL,
				OllamaModel:    model,
				OpenCodeURL:    opencodeURL,
				OpenCodeAPIKey: opencodeKey,
				DefaultLang:    "go",
			}

			session, err := godecomp.Open(binaryPath, cfg)
			if err != nil {
				return fmt.Errorf("opening binary: %w", err)
			}

			return session.StartTUI()
		},
	}
}

// newSymbolsCmd creates the "symbols" subcommand.
func newSymbolsCmd() *cobra.Command {
	var symType string

	cmd := &cobra.Command{
		Use:   "symbols <binary>",
		Short: "List symbols from a binary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			binaryPath := args[0]

			b, err := binary.Load(binaryPath)
			if err != nil {
				return fmt.Errorf("loading binary: %w", err)
			}

			switch symType {
			case "functions", "func", "":
				funcs := symbols.FunctionList(b)
				fmt.Printf("Functions in %s (%d total):\n\n", binaryPath, len(funcs))
				for _, sym := range funcs {
					fmt.Printf("  0x%016x  %-8s  %s\n", sym.Address, sym.Type, sym.Name)
				}

			case "imports":
				fmt.Printf("Imports in %s (%d total):\n\n", binaryPath, len(b.Imports))
				for _, imp := range b.Imports {
					if imp.Library != "" && imp.Name != "" {
						fmt.Printf("  %-40s  %s\n", imp.Name, imp.Library)
					} else if imp.Name != "" {
						fmt.Printf("  %s\n", imp.Name)
					} else if imp.Library != "" {
						fmt.Printf("  (library) %s\n", imp.Library)
					}
				}

			case "exports", "all":
				fmt.Printf("All symbols in %s (%d total):\n\n", binaryPath, len(b.Symbols))
				for _, sym := range b.Symbols {
					fmt.Printf("  0x%016x  %-8s  %s\n", sym.Address, sym.Type, sym.Name)
				}

			default:
				return fmt.Errorf("unknown symbol type %q; use functions, imports, or exports", symType)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&symType, "type", "t", "functions",
		"Symbol type to list (functions, imports, exports)")

	return cmd
}

// newStringsCmd creates the "strings" subcommand.
func newStringsCmd() *cobra.Command {
	var filter string

	cmd := &cobra.Command{
		Use:   "strings <binary>",
		Short: "Extract embedded strings from a binary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			binaryPath := args[0]

			b, err := binary.Load(binaryPath)
			if err != nil {
				return fmt.Errorf("loading binary: %w", err)
			}

			strs := symbols.FilterStrings(b, filter)
			fmt.Printf("Strings in %s (%d found):\n\n", binaryPath, len(strs))
			for _, s := range strs {
				fmt.Printf("  0x%08x  [%-12s]  %s\n", s.Offset, s.Section, s.Value)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&filter, "filter", "f", "", "Filter strings by keyword")

	return cmd
}

// newAskCmd creates the "ask" subcommand.
func newAskCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ask <binary> <question>",
		Short: "Ask a question about the binary using AI",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			binaryPath := args[0]
			question := args[1]

			cfg := godecomp.Config{
				OllamaURL:      ollamaURL,
				OllamaModel:    model,
				OpenCodeURL:    opencodeURL,
				OpenCodeAPIKey: opencodeKey,
			}

			session, err := godecomp.Open(binaryPath, cfg)
			if err != nil {
				return fmt.Errorf("opening binary: %w", err)
			}

			b := session.Binary
			funcs := session.Symbols()
			strs := session.Strings()

			// Build a summary of the binary
			summary := fmt.Sprintf(`Binary Analysis Summary:
File: %s
Format: %s
Architecture: %s (%d-bit)
OS: %s
Functions: %d
Imports: %d
Strings: %d

Top functions:
`,
				b.Path, b.Format, b.Arch, b.Bits, b.OS,
				len(funcs), len(b.Imports), len(strs))

			for i, fn := range funcs {
				if i >= 20 {
					summary += fmt.Sprintf("  ... and %d more\n", len(funcs)-20)
					break
				}
				summary += fmt.Sprintf("  - %s (0x%x)\n", fn.Name, fn.Address)
			}

			summary += "\nTop imports:\n"
			for i, imp := range b.Imports {
				if i >= 20 {
					break
				}
				if imp.Name != "" {
					summary += fmt.Sprintf("  - %s from %s\n", imp.Name, imp.Library)
				}
			}

			userPrompt := fmt.Sprintf("%s\nQuestion: %s", summary, question)

			ollama := ai.NewOllama(ollamaURL, model)
			ctx := context.Background()

			if !ollama.Available(ctx) {
				return fmt.Errorf("Ollama is not available at %s", ollamaURL)
			}

			sysPrompt := "You are a binary analysis expert. Answer questions about binary files based on their metadata, symbols, and imports."

			ch := make(chan ai.StreamChunk, 100)
			if err := ollama.Stream(ctx, ai.CompletionRequest{
				SystemPrompt: sysPrompt,
				UserPrompt:   userPrompt,
				Model:        model,
			}, ch); err != nil {
				return fmt.Errorf("starting stream: %w", err)
			}

			for chunk := range ch {
				if chunk.Error != nil {
					return fmt.Errorf("stream error: %w", chunk.Error)
				}
				if chunk.Done {
					break
				}
				fmt.Print(chunk.Text)
			}
			fmt.Println()

			return nil
		},
	}
}

// newModelsCmd creates the "models" subcommand.
func newModelsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "models",
		Short: "List available Ollama models",
		RunE: func(cmd *cobra.Command, args []string) error {
			type tagsResponse struct {
				Models []struct {
					Name       string `json:"name"`
					ModifiedAt string `json:"modified_at"`
					Size       int64  `json:"size"`
				} `json:"models"`
			}

			ctx := context.Background()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ollamaURL+"/api/tags", nil)
			if err != nil {
				return fmt.Errorf("creating request: %w", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("connecting to Ollama at %s: %w", ollamaURL, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("Ollama returned status %d", resp.StatusCode)
			}

			var result tagsResponse
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return fmt.Errorf("decoding response: %w", err)
			}

			if len(result.Models) == 0 {
				fmt.Println("No models found. Pull one with: ollama pull deepseek-coder:latest")
				return nil
			}

			fmt.Printf("Available Ollama models at %s:\n\n", ollamaURL)
			for _, m := range result.Models {
				sizeGB := float64(m.Size) / (1024 * 1024 * 1024)
				fmt.Printf("  %-40s  %.1f GB\n", m.Name, sizeGB)
			}

			return nil
		},
	}
}

// langExtension returns the file extension for a given language.
func langExtension(lang string) string {
	return decompiler.LangExtension(lang)
}
