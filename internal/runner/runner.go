package runner

import (
	"context"
	"sync"
	"time"

	"github.com/selimozcann/RedirectHunter/internal/model"
	"github.com/selimozcann/RedirectHunter/internal/trace"
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
	out := make([]model.Result, len(targets))
	mu := &sync.Mutex{}
	var (
		rateCh <-chan time.Time
		ticker *time.Ticker
	)
	if r.cfg.RateLimit > 0 {
		ticker = time.NewTicker(time.Second / time.Duration(r.cfg.RateLimit))
		rateCh = ticker.C
		defer ticker.Stop()
	}

	type job struct {
		idx    int
		target string
	}

	jobs := make(chan job)
	wg := sync.WaitGroup{}
	for i := 0; i < r.cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jb := range jobs {
				if rateCh != nil {
					select {
					case <-ctx.Done():
						return
					case <-rateCh:
					}
				}
				res := r.tracer.Trace(ctx, jb.target, r.cfg.MaxChain, r.cfg.JSSCAN)
				mu.Lock()
				out[jb.idx] = res
				mu.Unlock()
			}
		}()
	}

	go func() {
		for i, t := range targets {
			if ctx.Err() != nil {
				break
			}
			jobs <- job{idx: i, target: t}
		}
		close(jobs)
	}()

	wg.Wait()
	return out
}
