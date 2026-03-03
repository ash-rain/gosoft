package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OllamaProvider implements the Provider interface for Ollama.
type OllamaProvider struct {
	BaseURL string // default "http://localhost:11434"
	Model   string // default "minimax-m2.5:cloud"
	client  *http.Client
}

// NewOllama creates a new OllamaProvider.
func NewOllama(baseURL, model string) *OllamaProvider {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "minimax-m2.5:cloud"
	}
	return &OllamaProvider{
		BaseURL: baseURL,
		Model:   model,
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// Name returns the provider name.
func (o *OllamaProvider) Name() string { return "ollama" }

// Available checks if Ollama is running and accessible.
func (o *OllamaProvider) Available(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.BaseURL+"/api/tags", nil)
	if err != nil {
		return false
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type ollamaGenerateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaGenerateResponse struct {
	Model     string `json:"model"`
	Response  string `json:"response"`
	Done      bool   `json:"done"`
	CreatedAt string `json:"created_at"`
}

// Complete sends a non-streaming completion request to Ollama.
func (o *OllamaProvider) Complete(ctx context.Context, req CompletionRequest) (string, error) {
	model := req.Model
	if model == "" {
		model = o.Model
	}

	// Build full prompt from system + user
	fullPrompt := buildOllamaPrompt(req.SystemPrompt, req.UserPrompt)

	body := ollamaGenerateRequest{
		Model:  model,
		Prompt: fullPrompt,
		Stream: false,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshaling ollama request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.BaseURL+"/api/generate", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("creating ollama request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("calling ollama API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result ollamaGenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding ollama response: %w", err)
	}

	return result.Response, nil
}

// Stream sends a streaming completion request to Ollama.
func (o *OllamaProvider) Stream(ctx context.Context, req CompletionRequest, out chan<- StreamChunk) error {
	model := req.Model
	if model == "" {
		model = o.Model
	}

	fullPrompt := buildOllamaPrompt(req.SystemPrompt, req.UserPrompt)

	body := ollamaGenerateRequest{
		Model:  model,
		Prompt: fullPrompt,
		Stream: true,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling ollama stream request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.BaseURL+"/api/generate", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("creating ollama stream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("calling ollama stream API: %w", err)
	}

	go func() {
		defer resp.Body.Close()
		defer close(out)

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			out <- StreamChunk{
				Error: fmt.Errorf("ollama stream API returned status %d: %s", resp.StatusCode, string(respBody)),
				Done:  true,
			}
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}

			var chunk ollamaGenerateResponse
			if err := json.Unmarshal([]byte(line), &chunk); err != nil {
				out <- StreamChunk{
					Error: fmt.Errorf("decoding ollama stream chunk: %w", err),
					Done:  true,
				}
				return
			}

			if chunk.Done {
				out <- StreamChunk{Done: true}
				return
			}

			out <- StreamChunk{Text: chunk.Response}
		}

		if err := scanner.Err(); err != nil {
			out <- StreamChunk{
				Error: fmt.Errorf("reading ollama stream: %w", err),
				Done:  true,
			}
		}
	}()

	return nil
}

// buildOllamaPrompt combines system and user prompts.
func buildOllamaPrompt(system, user string) string {
	if system == "" {
		return user
	}
	return fmt.Sprintf("System: %s\n\n%s", system, user)
}

// ListModels returns the list of available Ollama models.
func (o *OllamaProvider) ListModels(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.BaseURL+"/api/tags", nil)
	if err != nil {
		return nil, fmt.Errorf("creating list models request: %w", err)
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing ollama models: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding models response: %w", err)
	}

	var names []string
	for _, m := range result.Models {
		names = append(names, m.Name)
	}
	return names, nil
}
