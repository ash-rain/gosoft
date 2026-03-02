package ai

import (
	"context"
	"fmt"
)

// Router tries providers in order, using the first available one.
type Router struct {
	providers []Provider
}

// NewRouter creates a new Router with the given providers.
func NewRouter(providers ...Provider) *Router {
	return &Router{providers: providers}
}

// Name returns the router name.
func (r *Router) Name() string { return "router" }

// Available returns true if any provider is available.
func (r *Router) Available(ctx context.Context) bool {
	for _, p := range r.providers {
		if p.Available(ctx) {
			return true
		}
	}
	return false
}

// Complete tries providers in order, using the first available one.
func (r *Router) Complete(ctx context.Context, req CompletionRequest) (string, error) {
	for _, p := range r.providers {
		if p.Available(ctx) {
			return p.Complete(ctx, req)
		}
	}
	return "", fmt.Errorf("no AI provider available")
}

// Stream tries providers in order, using the first available one.
func (r *Router) Stream(ctx context.Context, req CompletionRequest, out chan<- StreamChunk) error {
	for _, p := range r.providers {
		if p.Available(ctx) {
			return p.Stream(ctx, req, out)
		}
	}
	return fmt.Errorf("no AI provider available")
}
