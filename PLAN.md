# GoDecomp — Multi-Platform AI-Powered Decompiler

> A Go-based decompiler with CLI, TUI, and desktop GUI that leverages Ollama (local LLMs) and
> free cloud models to decompile binary files to any target language, explore symbols/resources,
> and reason about disassembly output.

---

## Vision

Most decompilers (Ghidra, IDA, Binary Ninja) are heavy, proprietary GUI tools with steep
learning curves. GoDecomp ships in three forms: a scriptable **CLI**, a keyboard-driven **TUI**,
and a polished **desktop GUI** (Wails + React) — all sharing the same Go core. Local Ollama
models mean no API keys and no data leaving the machine. Free cloud models are available as
an optional fallback for higher-quality output.

---

## Core Goals

| Goal | Description |
|------|-------------|
| **Multi-platform** | Supports x86, x86-64, ARM, ARM64, MIPS, RISC-V, WASM |
| **Any target language** | LLM translates disassembly → Go, C, Rust, Python, TS, etc. |
| **Local-first AI** | Ollama for fully offline operation (no API keys required) |
| **Free cloud fallback** | OpenCode-compatible free model endpoints as optional fallback |
| **Resource explorer** | Browse strings, symbols, imports, sections, embedded resources |
| **TUI + CLI** | Both interactive (Bubble Tea TUI) and piped/scriptable CLI modes |
| **Desktop GUI** | Native cross-platform app (Wails + React) with hex view, call graph, chat |
| **Extensible** | Plugin architecture for new architectures and output languages |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              GoDecomp                                        │
├────────────┬─────────────────────────┬──────────────────┬────────────────────┤
│  CLI Layer │   TUI Layer             │   GUI Layer       │  godecomp library  │
│  (Cobra)   │   (Bubble Tea)          │   (Wails + React) │  (importable pkg)  │
│            │   Explorer/Decompile    │   Desktop App     │                    │
└────────────┴─────────────────────────┴──────────────────┴────────────────────┘
                                        │
                       ┌────────────────▼────────────────┐
                       │           Core Pipeline          │
                       │                                 │
                       │   Binary ──► Disassembler        │
                       │               │                 │
                       │               ▼                 │
                       │           Symbol / Resource     │
                       │           Extractor             │
                       │               │                 │
                       │               ▼                 │
                       │           Context Builder       │
                       │   (function graph, strings,     │
                       │    cross-refs, types)           │
                       │               │                 │
                       │               ▼                 │
                       │         AI Provider Router      │
                       │      ┌──────────┬──────────┐    │
                       │      │ Ollama   │ OpenCode │    │
                       │      │ (local)  │ (cloud)  │    │
                       │      └──────────┴──────────┘    │
                       │               │                 │
                       │               ▼                 │
                       │        Source Code Output       │
                       └─────────────────────────────────┘
```

---

## Project Structure

```
gosoft/
├── cmd/
│   └── godecomp/
│       └── main.go               # CLI/TUI entry point
├── gui/                          # Wails desktop app (separate binary)
│   ├── main.go                   # Wails entry point
│   ├── app.go                    # Wails App struct — binds Go methods to JS
│   ├── frontend/                 # Vue 3 + TypeScript UI
│   │   ├── src/
│   │   │   ├── App.vue
│   │   │   ├── components/
│   │   │   │   ├── BinaryTree.vue      # Sidebar: functions/imports/symbols tree
│   │   │   │   ├── HexViewer.vue       # Canvas-rendered hex dump with highlights
│   │   │   │   ├── DisasmPane.vue      # Disassembly with address + mnemonic highlight
│   │   │   │   ├── SourcePane.vue      # Decompiled source via Monaco editor
│   │   │   │   ├── CallGraph.vue       # Interactive D3 call graph (zoom/pan)
│   │   │   │   ├── ChatPanel.vue       # AI chat sidebar with markdown
│   │   │   │   ├── ResourceBrowser.vue # Strings, URLs, certs, embedded files
│   │   │   │   ├── StatusBar.vue       # Binary info + Ollama health indicator
│   │   │   │   └── Settings.vue        # Model / provider config panel
│   │   │   ├── stores/
│   │   │   │   ├── binary.ts           # Pinia: loaded binary state
│   │   │   │   ├── chat.ts             # Pinia: chat history
│   │   │   │   └── settings.ts         # Pinia: user preferences
│   │   │   └── styles/
│   │   │       └── matrix.css          # Tailwind Matrix theme vars + animations
│   │   ├── package.json
│   │   └── vite.config.ts
│   └── wails.json
├── internal/
│   ├── binary/
│   │   ├── loader.go             # ELF, PE, Mach-O, WASM loaders
│   │   ├── pe.go
│   │   ├── elf.go
│   │   ├── macho.go
│   │   └── wasm.go
│   ├── disasm/
│   │   ├── disassembler.go       # Interface + dispatcher
│   │   ├── capstone.go           # CGo or subprocess bridge to Capstone
│   │   └── gapstone.go           # Pure-Go fallback (gapstone)
│   ├── symbols/
│   │   ├── extractor.go          # Symbols, imports, exports
│   │   └── resources.go          # Embedded strings, icons, certs, etc.
│   ├── context/
│   │   └── builder.go            # Builds rich context for LLM prompt
│   ├── ai/
│   │   ├── provider.go           # Provider interface
│   │   ├── ollama.go             # Ollama REST client
│   │   ├── opencode.go           # OpenCode / free cloud adapter
│   │   └── router.go             # Local-first routing with fallback
│   ├── decompiler/
│   │   ├── pipeline.go           # Orchestrates disasm → context → AI
│   │   ├── function.go           # Per-function decompilation unit
│   │   └── languages.go          # Target language prompts & formatters
│   └── tui/
│       ├── app.go                # Root Bubble Tea model
│       ├── explorer.go           # Symbol/resource browser pane
│       ├── viewer.go             # Decompiled source viewer pane
│       └── chat.go               # Inline AI chat about the binary
├── pkg/
│   └── godecomp/                 # Public library API (shared by CLI + GUI)
│       └── api.go
├── configs/
│   └── models.yaml               # Default model configs per task
├── go.mod
├── go.sum
└── PLAN.md
```

---

## Phases

### Phase 1 — Foundation (Core Pipeline)

**Goal:** Load a binary, disassemble it, and print LLM-decompiled output to stdout.

Tasks:
- [ ] Set up Go module (`gosoft/godecomp`)
- [ ] Implement binary loader with format autodetection (ELF, PE, Mach-O)
- [ ] Integrate disassembler — use `gapstone` (pure Go bindings for Capstone) for x86/ARM
- [ ] Implement symbol/string extractor
- [ ] Build Ollama provider client (streaming REST, `/api/generate`)
- [ ] Build context builder: assemble function disassembly + surrounding symbols into a prompt
- [ ] Implement basic CLI: `godecomp decompile <binary> --func <name> --lang go`
- [ ] Write system prompt templates per target language

**Deliverable:** `godecomp decompile ./target --lang python` prints decompiled Python to stdout.

---

### Phase 2 — Resource Explorer TUI

**Goal:** Interactive terminal UI to browse binary internals.

Tasks:
- [ ] Set up Bubble Tea application shell with pane layout
- [ ] Symbol browser pane: functions, imports, exports (filterable list)
- [ ] Strings / resources pane: embedded text, URLs, certs, icons
- [ ] Section map pane: segments, permissions, entropy visualization
- [ ] Select function → trigger decompile → show in viewer pane
- [ ] Keybindings: vim-style navigation, `/` to search, `d` to decompile

**Deliverable:** `godecomp explore ./target` opens the TUI.

---

### Phase 3 — Multi-Architecture & Language Support

**Goal:** Broaden coverage and output quality.

Tasks:
- [ ] Add ARM64, MIPS, RISC-V disassembly via gapstone/Capstone
- [ ] Add WASM binary support (custom parser + WAT disassembly)
- [ ] Add PE/Mach-O loaders with import table parsing
- [ ] Language profiles: C, Rust, TypeScript, Java pseudocode, Go
- [ ] Multi-pass decompilation: first pass for types/structs, second for logic
- [ ] Confidence scoring: LLM returns structured JSON + source

---

### Phase 4 — OpenCode / Free Cloud Integration

**Goal:** Fallback to free cloud models when local Ollama is unavailable or insufficient.

Tasks:
- [ ] Implement OpenCode API client (OpenAI-compatible endpoint)
- [ ] AI provider router: prefer Ollama, fall back to OpenCode, configurable
- [ ] Support Groq, Together AI, Mistral free tiers via API key config
- [ ] Rate limiting and retry logic in router
- [ ] Config file: `~/.config/godecomp/config.yaml` for keys and preferences

---

### Phase 5 — Inline AI Chat & Reasoning

**Goal:** Ask questions about the binary in natural language.

Tasks:
- [ ] Chat pane in TUI: ask "what does this function do?", "find crypto routines"
- [ ] Maintain conversation context per session with binary summary in system prompt
- [ ] CLI mode: `godecomp ask ./target "find all network calls"`
- [ ] Cross-reference awareness: link LLM answers back to symbol locations

---

### Phase 6 — Advanced Features

**Goal:** Polish and power-user capabilities.

Tasks:
- [ ] Batch decompile entire binary to a project directory
- [ ] Export to compilable project: `godecomp export ./target --lang rust --out ./output`
- [ ] Struct/type inference from memory access patterns
- [ ] Plugin system: custom language templates via YAML/WASM plugins
- [ ] LSP integration hint: output location comments for editor navigation
- [ ] Binary diffing: compare two versions of a binary, summarize changes via AI

---

### Phase 7 — Desktop GUI (Wails)

**Goal:** A polished, native desktop application built on Wails v2 with a React/TypeScript
frontend. All heavy lifting stays in the Go core — the GUI is purely a rich view layer.

#### Layout

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  GoDecomp  [File ▾] [View ▾] [Tools ▾]      [●] deepseek-coder:33b ▾  [⚙] │
├───────────────────┬─────────────────────────────────┬───────────────────────┤
│  Binary Explorer  │  [Hex] [Disasm] [Source] [Graph]│  AI Chat              │
│                   │                                 │                       │
│ ▼ /usr/bin/ls     │  func main() {                  │  You: what does this  │
│   ▼ Functions     │    args := os.Args              │  function do?         │
│     main          │    if len(args) < 2 {            │                       │
│     usage         │      usage()                    │  AI: This is the      │
│     listDir  ◀──  │      os.Exit(1)                 │  entry point. It      │
│     sortFiles     │    }                            │  parses arguments,    │
│   ▶ Imports       │    result := listDir(args[1])   │  calls listDir() and  │
│   ▶ Exports       │    sortFiles(result)             │  sorts the output...  │
│   ▶ Strings (42)  │    printOutput(result)          │                       │
│   ▶ Resources (3) │  }                              │  ▸ [Ask anything...]  │
│                   │                                 │                       │
│  [Open Binary...] │  [⚡ Decompile]  Lang: [Go ▾]   │  [Clear]  [Export]    │
└───────────────────┴─────────────────────────────────┴───────────────────────┘
│  Status: Ready · x86-64 ELF · 142 functions · Ollama online               │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Panes

| Pane | Description |
|------|-------------|
| **Binary Explorer** | Collapsible tree of functions, imports, exports, strings, resources. Click to navigate. |
| **Hex Viewer** | Raw bytes with offset column, ASCII sidebar, click-to-highlight linked to disasm |
| **Disassembly** | Syntax-highlighted disassembly; click address to jump, right-click to decompile |
| **Source Pane** | Monaco editor (read-only) with the AI-decompiled output; token-by-token streaming |
| **Call Graph** | D3.js force-directed graph; click node to open that function |
| **AI Chat** | Persistent chat with binary context; answers link back to symbol locations |
| **Settings** | Ollama URL, model picker, target language default, theme |

#### Tasks
- [ ] Scaffold Wails v2 project under `gui/`
- [ ] Wire `pkg/godecomp` API as Wails-bound Go methods (exposed to JS via `wails.json`)
- [ ] Scaffold Wails v2 project with Vue 3 + Vite template
- [ ] Configure Tailwind CSS with Matrix theme (green `#00ff41` on black `#0d0d0d`, monospace font)
- [ ] Pinia stores: `useBinaryStore`, `useChatStore`, `useSettingsStore`
- [ ] Binary Explorer component — recursive `<TreeNode>` with `@tanstack/vue-virtual`
- [ ] Hex Viewer using `<canvas>` rendering for performance on large binaries
- [ ] Disassembly pane with address column, mnemonic highlight via custom Vue directive
- [ ] Monaco editor integration for source output — readonly, language from target lang setting
- [ ] Streaming support: Wails event bus (`EventsOn`) → Pinia store → `v-for` renders tokens live
- [ ] Call graph pane: D3.js force-directed, zoom/pan, click node → navigate to function
- [ ] AI Chat panel with `vue-markdown-it`, green bubble styling, auto-scroll
- [ ] Drag-and-drop binary loading (HTML5 drop zone on the whole window)
- [ ] Settings panel: Ollama URL, model picker (fetches `/api/tags` from Ollama), target language
- [ ] Status bar: binary name, arch, function count, current model, Ollama green/red dot
- [ ] Light theme option (Matrix Green stays; background flips to `#f0f0f0` with green accents)
- [ ] Build pipeline: `wails build` → single `.app` / `.exe` / Linux binary, no runtime deps

**Deliverable:** `godecomp-gui` native desktop app on macOS, Windows, and Linux.

---

## AI Model Strategy

### Local (Ollama) — Default

| Task | Recommended Model | Why |
|------|------------------|-----|
| Decompilation (fast) | `codellama:13b` | Code-optimized, fast on consumer GPU |
| Decompilation (quality) | `deepseek-coder:33b` | Best free local code model |
| Explanation / chat | `llama3.1:8b` | Fast, conversational |
| Type inference | `deepseek-coder:7b` | Lightweight for structured tasks |

### Free Cloud (OpenCode / fallback)

| Provider | Free Model | Use Case |
|----------|-----------|---------|
| Groq | `llama-3.3-70b` | Fast cloud inference |
| Together AI | `deepseek-coder-v2` | High quality code |
| Mistral | `mistral-small` | Good code + explanation |
| OpenCode | Configured via user | User-provided free tier |

### Prompt Strategy

```
[SYSTEM]
You are a binary decompilation expert. Given x86-64 disassembly with symbol hints,
produce clean, idiomatic {TARGET_LANGUAGE} code that is functionally equivalent.
Preserve all logic. Add brief inline comments for non-obvious operations.
Output ONLY the source code block.

[USER]
Function: {FUNC_NAME}
Binary: {BINARY_NAME} ({ARCH}, {OS})
Known symbols: {SYMBOL_CONTEXT}
Strings referenced: {STRING_REFS}
Cross-references: {XREFS}

Disassembly:
{DISASSEMBLY}

Decompile to {TARGET_LANGUAGE}:
```

---

## Key Dependencies

#### Go / Backend

| Package | Purpose |
|---------|---------|
| `github.com/charmbracelet/bubbletea` | TUI framework |
| `github.com/charmbracelet/lipgloss` | TUI styling |
| `github.com/charmbracelet/bubbles` | TUI components (list, viewport, textinput) |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/knightsc/gapstone` | Pure-Go Capstone disassembly bindings |
| `debug/elf`, `debug/pe`, `debug/macho` | Go stdlib binary parsers |
| `github.com/spf13/viper` | Config file management |
| `github.com/wailsapp/wails/v2` | Desktop GUI framework (Go ↔ JS bridge) |
| Standard `net/http` | Ollama / cloud REST clients |

#### Frontend (GUI — Vue 3 + Tailwind Matrix Theme)

| Package | Purpose |
|---------|---------|
| `vue` + `@vitejs/plugin-vue` | Vue 3 Composition API frontend |
| `tailwindcss` | Utility-first CSS |
| `@tailwindcss/typography` | Prose styling for AI chat output |
| `tailwind-matrix` theme | Green-on-black Matrix terminal aesthetic |
| `monaco-editor` (via `@guolao/vue-monaco-editor`) | Source code viewer with syntax highlight |
| `d3` | Call graph force layout |
| `@tanstack/vue-virtual` | Virtualized lists for large symbol tables |
| `vue-markdown-it` | Markdown rendering for AI chat responses |
| `pinia` | State management (binary session, chat history) |
| `vite` | Build tool |

---

## Configuration (`~/.config/godecomp/config.yaml`)

```yaml
ai:
  provider: ollama          # ollama | opencode | groq | together | auto
  ollama_url: http://localhost:11434
  default_model: deepseek-coder:33b
  fallback_provider: groq
  groq_api_key: ""
  together_api_key: ""
  opencode_url: ""

decompile:
  default_language: go
  max_function_size: 500    # instructions; larger functions are chunked
  streaming: true

tui:
  theme: dark               # dark | light
  vim_keys: true

gui:
  theme: matrix             # matrix | light
  font: JetBrains Mono
  font_size: 13
  window_width: 1400
  window_height: 900
```

---

## CLI Interface

```bash
# Decompile a single function
godecomp decompile ./target --func main --lang rust

# Decompile all functions, output to directory
godecomp decompile ./target --lang python --all --out ./decompiled/

# Explore binary in TUI
godecomp explore ./target

# Ask a question about the binary
godecomp ask ./target "what libraries does this use and what does it phone home to?"

# List symbols
godecomp symbols ./target --type functions

# Extract embedded strings/resources
godecomp resources ./target --filter urls
```

---

## Non-Goals (Explicitly Out of Scope)

- No proprietary format support (IDA .idb, BinaryNinja databases)
- No dynamic analysis / emulation (Unicorn, QEMU) — static analysis only
- No malware distribution or generation assistance

---

## Success Criteria

- [ ] Decompiles a simple C binary to readable Go/Python within 30 seconds on consumer hardware
- [ ] TUI explorer loads a 5MB binary and renders symbol list within 2 seconds
- [ ] GUI loads a 5MB binary, renders hex and symbol tree within 1 second
- [ ] Streaming decompilation tokens appear in the Monaco pane with <200ms first-token latency
- [ ] Call graph renders cleanly for binaries with up to 1000 functions
- [ ] Fallback to free cloud works transparently when Ollama is offline
- [ ] All target languages produce syntactically valid output >80% of the time on simple functions
- [ ] CLI/TUI: single static binary from `go build`, no external deps
- [ ] GUI: `wails build` produces a signed, self-contained `.app` / `.exe` / Linux AppImage

---

## Getting Started (After Implementation)

```bash
# Pull a local model
ollama pull deepseek-coder:33b

# --- CLI / TUI ---
go install github.com/yourusername/gosoft/cmd/godecomp@latest

# Explore a binary in the TUI
godecomp explore /usr/bin/ls

# Decompile to Go via CLI
godecomp decompile /usr/bin/ls --func main --lang go

# --- Desktop GUI ---
# Install (download release binary or build from source)
wails build ./gui

# Launch
open GoDecomp.app            # macOS
./GoDecomp                   # Linux
GoDecomp.exe                 # Windows
```

### GUI Theme Preview (Matrix)

```
┌──────────────────────────────────────────────────────────┐
│ ░░░  GoDecomp                            [●] deepseek ▾  │  ← #0d0d0d bg
│ ░░░──────────────────────────────────────────────────░░░ │
│ ░░░  ▼ main          │ func main() {                 ░░░ │  ← #00ff41 text
│ ░░░    listDir  ◀──  │   args := os.Args             ░░░ │
│ ░░░    sortFiles     │   if len(args) < 2 {          ░░░ │
│ ░░░  ▶ Imports       │     usage()                   ░░░ │
│ ░░░  ▶ Strings (42)  │   }                           ░░░ │
│ ░░░                  │                               ░░░ │
│ ░░░  [Open Binary]   │  [⚡ Decompile]  Lang: [Go ▾] ░░░ │
│ ░░░──────────────────────────────────────────────────░░░ │
│ ░░░  Ready · x86-64 ELF · 142 fns · Ollama ● online  ░░░ │
└──────────────────────────────────────────────────────────┘
```

Fonts: `JetBrains Mono` / `Fira Code` · Accent: `#00ff41` · Background: `#0d0d0d` · Border: `#1a3d1a`
