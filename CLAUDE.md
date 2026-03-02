# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build -o godecomp ./cmd/godecomp

# Run all tests
go test ./...

# Run a single package's tests
go test ./internal/binary/...
go test ./internal/disasm/...

# Run a specific test
go test -run TestLoadELF ./internal/binary/

# Vet
go vet ./...
```

## Architecture

The project is a binary decompiler. Data flows in one direction through four layers:

```
CLI/TUI  →  pkg/godecomp (Session API)  →  internal pipeline  →  AI provider
```

**Entry point**: `cmd/godecomp/main.go` — Cobra CLI with six subcommands (`decompile`, `explore`, `symbols`, `strings`, `ask`, `models`). `explore` launches the TUI; all others are scriptable.

**Public API**: `pkg/godecomp/api.go` — `Open(path, Config)` returns a `Session` that wraps a loaded `*Binary` and a `*Pipeline`. The CLI and TUI both go through this.

**Core pipeline** (`internal/decompiler/pipeline.go`):
1. `symbols.FindSymbol` locates the target function
2. `disasm.New(arch)` picks the right disassembler — x86, ARM, or `"il"` for .NET
3. `context.Build` finds the function's bytes in the binary's sections and disassembles them, then collects nearby symbols and strings into a `FunctionContext`
4. `context.FormatPrompt` assembles the LLM prompt
5. `provider.Complete` or `provider.Stream` calls the AI

**Binary loading** (`internal/binary/`): `Load(path)` reads magic bytes, then calls the right loader. For PE files it additionally checks DataDirectory[14] — a non-zero CLR header means `.NET`, which routes to `loadDotNet` instead of `loadPE`. .NET loading parses ECMA-335 metadata tables (TypeDef + MethodDef) to extract type/method symbols, and stores each method's IL bytes as a named section `"IL:Namespace.Type::Method"` with `Offset = RVA`. This lets `context.Build` find IL bytes by address.

**Disassemblers** (`internal/disasm/`): All implement `Disassembler { Disassemble([]byte, uint64) ([]Instruction, error); Arch() string }`. `"il"` maps to the ECMA-335 IL disassembler in `il.go`.

**AI providers** (`internal/ai/`): `Provider` interface with `Complete`, `Stream`, `Available`. `Router` wraps multiple providers and tries each in order — Ollama first, then OpenCode. `StreamChunk` carries tokens over a Go channel.

**TUI** (`internal/tui/app.go`): Bubble Tea model. Left panel has four list tabs (Functions/Strings/Imports/Sections) switched with `f/s/i/x`. Right panel has three viewport tabs (Source/Disasm/Hex) switched with `1/2/3`. Decompilation uses `Pipeline.DecompileFunctionStream` and feeds chunks back via `streamChunkMsg`. Chat uses `Pipeline.AskStream`. The `"IL:"` prefix on section names is filtered out of the Sections tab.

## Key Conventions

- **Section.Offset** stores the file offset for ELF/PE/MachO sections, but **RVA** for .NET IL sections — this is intentional so `context.Build` can match `sym.Address` (also an RVA) against `sec.Offset`.
- `decompiler.LangExtension` and `decompiler.LangDisplayName` are the canonical source for language metadata — don't duplicate them in `main.go`.
- The `IL:` section name prefix is a convention used in two places: `loadDotNet` (creates them) and `tui/app.go` (filters them from the Sections list).
- The `m` key in the TUI is documented (README) as opening a model picker that lists locally downloaded Ollama models — it is not yet implemented in `app.go`.
