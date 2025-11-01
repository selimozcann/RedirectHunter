package main

import (
	"net/http"
	"testing"

	"github.com/selimozcann/RedirectHunter/internal/model"
)

func TestClassifyChain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		status   int
		chain    []model.Hop
		hasError bool
		want     resultKind
	}{
		{
			name:   "redirectWithOkFinal",
			status: http.StatusOK,
			chain: []model.Hop{
				{Status: http.StatusFound},
				{Status: http.StatusOK},
			},
			want: resultKindRedirect,
		},
		{
			name:   "redirectWithError",
			status: 0,
			chain: []model.Hop{
				{Status: http.StatusFound},
			},
			hasError: true,
			want:     resultKindRedirect,
		},
		{
			name:   "directOk",
			status: http.StatusOK,
			chain: []model.Hop{
				{Status: http.StatusOK},
			},
			want: resultKindOK,
		},
		{
			name:   "errorStatus",
			status: http.StatusNotFound,
			want:   resultKindError,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyChain(tt.status, tt.chain, tt.hasError); got != tt.want {
				t.Fatalf("classifyChain() = %v, want %v", got, tt.want)
			}
		})
	}
}
