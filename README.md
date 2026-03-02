# GoDecomp

AI-powered binary decompiler with a keyboard-driven TUI and scriptable CLI.
Supports ELF, PE, Mach-O, and .NET/Mono assemblies across x86, x86-64, ARM, ARM64, and MIPS.
Uses a local [Ollama](https://ollama.com) model by default — no API keys, no data leaves your machine.

```
┌──────────────────────────┬──────────────────────────────────────────────────┐
│ [F]uncs [S]trings ...    │ [1]Source  [2]Disasm  [3]Hex                    │
│ ──────────────────────   │ ────────────────────────────────────────────────  │
│ > Namespace.Type::Main   │  func Main() {                                   │
│   .ctor                  │    args := os.Args                               │
│   ParseArgs              │    if len(args) < 2 {                            │
│   PrintHelp              │      PrintHelp()                                 │
│   ...                    │      return                                      │
│                          │    }                                             │
│                          │  }                                               │
├──────────────────────────┴──────────────────────────────────────────────────┤
│ [tab] focus  [d] decompile  [l] lang  [c] chat  [?] help  [q] quit        │
│ /usr/bin/ls  linux/x86_64  ELF  lang:go  Ready                            │
└────────────────────────────────────────────────────────────────────────────┘
```

## Requirements

- **Go 1.21+**
- **[Ollama](https://ollama.com)** running locally (default: `http://localhost:11434`)
- At least one Ollama model pulled, e.g. `ollama pull deepseek-coder:7b`

## Build

```bash
git clone <repo>
cd gosoft

go build -o godecomp ./cmd/godecomp
```

Or install directly to `$GOPATH/bin`:

```bash
go install ./cmd/godecomp
```

## Run

### Interactive TUI

```bash
godecomp explore /usr/bin/ls
godecomp explore MyApp.exe          # PE or .NET assembly
godecomp explore MyAssembly.dll     # .NET/Mono DLL
```

### Decompile a function

```bash
# Single function, printed to stdout
godecomp decompile /usr/bin/ls --func main --lang go

# Stream output token-by-token
godecomp decompile /usr/bin/ls --func main --lang rust --stream

# Decompile all functions to a directory
godecomp decompile MyApp.exe --all --lang csharp --out ./src/
```

### List symbols

```bash
godecomp symbols /usr/bin/ls                    # functions (default)
godecomp symbols /usr/bin/ls --type imports
godecomp symbols /usr/bin/ls --type exports
```

### Extract strings

```bash
godecomp strings /usr/bin/ls
godecomp strings MyApp.exe --filter http        # filter by keyword
```

### Ask AI a question

```bash
godecomp ask /usr/bin/ls "what libraries does this use?"
godecomp ask MyApp.exe "find all network calls"
```

### List available Ollama models

```bash
godecomp models
```

## TUI Key Bindings

| Key | Action |
|-----|--------|
| `tab` | Switch focus between left and right panel |
| `j` / `k` or `↑` / `↓` | Navigate list |
| `/` | Filter current list |
| `esc` | Clear filter / close chat |
| `f` | Left tab: Functions |
| `s` | Left tab: Strings |
| `i` | Left tab: Imports |
| `x` | Left tab: Sections |
| `1` | Right tab: Source (decompiled output) |
| `2` | Right tab: Disassembly |
| `3` | Right tab: Hex dump |
| `d` / `enter` | Decompile selected function (or hex-view selected section) |
| `l` | Cycle target language |
| `c` | Open chat — ask AI about the binary |
| `?` | Help overlay |
| `q` / `ctrl+c` | Quit |

## Supported Formats & Architectures

| Format | Detection |
|--------|-----------|
| ELF | `\x7fELF` magic |
| PE (Windows) | `MZ` magic |
| .NET / Mono | PE + CLR metadata header (DataDirectory[14]) |
| Mach-O | `\xfe\xed\xfa\xce/cf` and fat binary magic |

| Architecture | Disassembler |
|---|---|
| x86 / x86-64 | Pure-Go x86 (`golang.org/x/arch`) |
| ARM / ARM64 | Pure-Go ARM |
| MIPS | Symbol extraction only |
| .NET IL / CIL | Built-in ECMA-335 IL disassembler |

## Target Languages

`go`, `c`, `rust`, `python`, `typescript`, `java`, `csharp`

Cycle through them with `l` in the TUI, or pass `--lang <name>` on the CLI.

## AI Providers

| Provider | Config | Notes |
|----------|--------|-------|
| Ollama (default) | `--ollama-url`, `--model` | Fully local, no API key |
| OpenCode / cloud | `--opencode-url`, `--opencode-key` | Free-tier cloud fallback |

The router prefers Ollama and falls back to the cloud provider if Ollama is unavailable.

Recommended models:

```bash
ollama pull deepseek-coder:7b     # fast, good quality
ollama pull deepseek-coder:33b    # best quality
ollama pull codellama:13b         # alternative
```

## Global Flags

```
--ollama-url   Ollama API URL          (default: http://localhost:11434)
--model        Model name              (default: deepseek-coder:7b)
--opencode-url OpenCode-compatible URL (optional)
--opencode-key OpenCode API key        (optional)
```

## Tests

```bash
go test ./...
```
