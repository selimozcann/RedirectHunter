package model

import "time"

// Hop represents a single step in a redirect chain.
type Hop struct {
	Index  int    `json:"index"`
	URL    string `json:"url"`
	Method string `json:"method"`
	Status int    `json:"status"`
	Via    string `json:"via"`
	Reason string `json:"reason,omitempty"`
	TimeMs int64  `json:"time_ms"`
	Final  bool   `json:"final"`
}

// Finding represents a detection within a redirect chain.
type Finding struct {
	Type     string            `json:"type"`
	AtHop    int               `json:"at_hop"`
	Severity string            `json:"severity"`
	Detail   string            `json:"detail"`
	Evidence map[string]string `json:"evidence,omitempty"`
}

// Result is the final output for a single scanned target.
type Result struct {
	Target     string    `json:"target"`
	Chain      []Hop     `json:"chain"`
	Findings   []Finding `json:"findings,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	DurationMs int64     `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
}
