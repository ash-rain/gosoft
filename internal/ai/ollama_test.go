package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// makeOllamaTagsHandler returns an HTTP handler that simulates Ollama's /api/tags endpoint.
func makeOllamaTagsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"models": []map[string]interface{}{
				{"name": "deepseek-coder:7b", "size": 1234567890},
			},
		})
	}
}

// makeOllamaGenerateHandler returns an HTTP handler that simulates Ollama's /api/generate endpoint.
func makeOllamaGenerateHandler(response string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			http.NotFound(w, r)
			return
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		stream, _ := req["stream"].(bool)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if stream {
			// NDJSON streaming response
			chunks := strings.Fields(response)
			for i, word := range chunks {
				text := word
				if i < len(chunks)-1 {
					text += " "
				}
				json.NewEncoder(w).Encode(map[string]interface{}{
					"response": text,
					"done":     false,
				})
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			// Send done
			json.NewEncoder(w).Encode(map[string]interface{}{
				"response": "",
				"done":     true,
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"response": response,
				"done":     true,
			})
		}
	}
}

func TestOllamaAvailable(t *testing.T) {
	// Start test server that returns 200 for /api/tags
	server := httptest.NewServer(makeOllamaTagsHandler())
	defer server.Close()

	provider := NewOllama(server.URL, "test-model")
	ctx := context.Background()

	if !provider.Available(ctx) {
		t.Error("expected Available() to return true")
	}
}

func TestOllamaNotAvailable(t *testing.T) {
	// Use a server that immediately closes connections
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	provider := NewOllama(server.URL, "test-model")
	ctx := context.Background()

	if provider.Available(ctx) {
		t.Error("expected Available() to return false for non-200 response")
	}
}

func TestOllamaComplete(t *testing.T) {
	expectedResponse := "func main() { fmt.Println(\"hello\") }"

	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", makeOllamaTagsHandler())
	mux.HandleFunc("/api/generate", makeOllamaGenerateHandler(expectedResponse))
	server := httptest.NewServer(mux)
	defer server.Close()

	provider := NewOllama(server.URL, "test-model")
	ctx := context.Background()

	result, err := provider.Complete(ctx, CompletionRequest{
		SystemPrompt: "You are a decompiler",
		UserPrompt:   "Decompile this function",
		Model:        "test-model",
	})

	if err != nil {
		t.Fatalf("Complete() returned error: %v", err)
	}

	if result != expectedResponse {
		t.Errorf("expected response %q, got %q", expectedResponse, result)
	}
}

func TestOllamaStream(t *testing.T) {
	expectedResponse := "func main() returns error"

	mux := http.NewServeMux()
	mux.HandleFunc("/api/tags", makeOllamaTagsHandler())
	mux.HandleFunc("/api/generate", makeOllamaGenerateHandler(expectedResponse))
	server := httptest.NewServer(mux)
	defer server.Close()

	provider := NewOllama(server.URL, "test-model")
	ctx := context.Background()

	out := make(chan StreamChunk, 100)
	err := provider.Stream(ctx, CompletionRequest{
		SystemPrompt: "You are a decompiler",
		UserPrompt:   "Decompile this",
		Model:        "test-model",
	}, out)

	if err != nil {
		t.Fatalf("Stream() returned error: %v", err)
	}

	var received strings.Builder
	for chunk := range out {
		if chunk.Error != nil {
			t.Fatalf("stream chunk error: %v", chunk.Error)
		}
		if chunk.Done {
			break
		}
		received.WriteString(chunk.Text)
	}

	// The streamed text should contain the words from the expected response
	result := received.String()
	if !strings.Contains(result, "func") {
		t.Errorf("expected stream to contain 'func', got %q", result)
	}
}

func TestBuildOllamaPrompt(t *testing.T) {
	// With system prompt
	result := buildOllamaPrompt("System: be helpful", "User message")
	if !strings.Contains(result, "System: be helpful") {
		t.Error("expected system prompt in result")
	}
	if !strings.Contains(result, "User message") {
		t.Error("expected user message in result")
	}

	// Without system prompt
	result = buildOllamaPrompt("", "Just user")
	if result != "Just user" {
		t.Errorf("expected 'Just user', got %q", result)
	}
}
