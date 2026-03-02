package ai

import "context"

// CompletionRequest holds the prompt and parameters for an AI request.
type CompletionRequest struct {
	SystemPrompt string
	UserPrompt   string
	Model        string
	Stream       bool
	Temperature  float32
}

// StreamChunk is one token chunk from streaming.
type StreamChunk struct {
	Text  string
	Done  bool
	Error error
}

// Provider is the interface for AI backends.
type Provider interface {
	Name() string
	Complete(ctx context.Context, req CompletionRequest) (string, error)
	Stream(ctx context.Context, req CompletionRequest, out chan<- StreamChunk) error
	Available(ctx context.Context) bool
}
