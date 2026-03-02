package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenCodeProvider talks to any OpenAI-compatible API.
type OpenCodeProvider struct {
	BaseURL string
	APIKey  string
	Model   string
	client  *http.Client
}

// NewOpenCode creates a new OpenCodeProvider.
func NewOpenCode(baseURL, apiKey, model string) *OpenCodeProvider {
	return &OpenCodeProvider{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Model:   model,
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// Name returns the provider name.
func (o *OpenCodeProvider) Name() string { return "opencode" }

// Available checks if the OpenCode API is accessible.
func (o *OpenCodeProvider) Available(ctx context.Context) bool {
	if o.BaseURL == "" || o.APIKey == "" {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.BaseURL+"/v1/models", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+o.APIKey)
	resp, err := o.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type openCodeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openCodeRequest struct {
	Model    string            `json:"model"`
	Messages []openCodeMessage `json:"messages"`
	Stream   bool              `json:"stream"`
}

type openCodeResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}

// Complete sends a non-streaming completion request.
func (o *OpenCodeProvider) Complete(ctx context.Context, req CompletionRequest) (string, error) {
	model := req.Model
	if model == "" {
		model = o.Model
	}

	messages := []openCodeMessage{
		{Role: "system", Content: req.SystemPrompt},
		{Role: "user", Content: req.UserPrompt},
	}

	body := openCodeRequest{
		Model:    model,
		Messages: messages,
		Stream:   false,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshaling opencode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.BaseURL+"/v1/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("creating opencode request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.APIKey)

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("calling opencode API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("opencode API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result openCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding opencode response: %w", err)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("opencode API returned no choices")
	}

	return result.Choices[0].Message.Content, nil
}

// Stream sends a streaming completion request using SSE format.
func (o *OpenCodeProvider) Stream(ctx context.Context, req CompletionRequest, out chan<- StreamChunk) error {
	model := req.Model
	if model == "" {
		model = o.Model
	}

	messages := []openCodeMessage{
		{Role: "system", Content: req.SystemPrompt},
		{Role: "user", Content: req.UserPrompt},
	}

	body := openCodeRequest{
		Model:    model,
		Messages: messages,
		Stream:   true,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling opencode stream request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.BaseURL+"/v1/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("creating opencode stream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.APIKey)
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("calling opencode stream API: %w", err)
	}

	go func() {
		defer resp.Body.Close()
		defer close(out)

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			out <- StreamChunk{
				Error: fmt.Errorf("opencode stream API returned status %d: %s", resp.StatusCode, string(respBody)),
				Done:  true,
			}
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()

			// SSE format: "data: {...}"
			if !strings.HasPrefix(line, "data: ") {
				continue
			}

			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				out <- StreamChunk{Done: true}
				return
			}

			var chunk openCodeResponse
			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				continue // Skip malformed chunks
			}

			if len(chunk.Choices) > 0 {
				content := chunk.Choices[0].Delta.Content
				if chunk.Choices[0].FinishReason == "stop" {
					out <- StreamChunk{Done: true}
					return
				}
				if content != "" {
					out <- StreamChunk{Text: content}
				}
			}
		}

		if err := scanner.Err(); err != nil {
			out <- StreamChunk{
				Error: fmt.Errorf("reading opencode stream: %w", err),
				Done:  true,
			}
			return
		}

		out <- StreamChunk{Done: true}
	}()

	return nil
}
