package runner

import (
	"context"
	"sync"
	"time"

	"redirecthunter/internal/model"
	"redirecthunter/internal/trace"
)

// Config holds settings for the runner.
type Config struct {
	Threads   int
	RateLimit int // requests per second, 0 = unlimited
	MaxChain  int
	JSSCAN    bool
}

// Runner coordinates concurrent scans.
type Runner struct {
	cfg    Config
	tracer *trace.Tracer
}

// New creates a new Runner.
func New(cfg Config, tracer *trace.Tracer) *Runner {
	return &Runner{cfg: cfg, tracer: tracer}
}

// Run processes targets and returns results.
func (r *Runner) Run(ctx context.Context, targets []string) []model.Result {
	out := make([]model.Result, 0, len(targets))
	mu := &sync.Mutex{}
	var rateCh <-chan time.Time
	if r.cfg.RateLimit > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(r.cfg.RateLimit))
		rateCh = ticker.C
	}

	jobs := make(chan string)
	wg := sync.WaitGroup{}
	for i := 0; i < r.cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if rateCh != nil {
					select {
					case <-ctx.Done():
						return
					case <-rateCh:
					}
				}
				res := r.tracer.Trace(ctx, t, r.cfg.MaxChain, r.cfg.JSSCAN)
				mu.Lock()
				out = append(out, res)
				mu.Unlock()
			}
		}()
	}

	go func() {
		for _, t := range targets {
			if ctx.Err() != nil {
				break
			}
			jobs <- t
		}
		close(jobs)
	}()

	wg.Wait()
	return out
}
