package main

import (
	"net/http"
	"testing"

	"github.com/selimozcann/RedirectHunter/internal/model"
	"github.com/selimozcann/RedirectHunter/internal/output"
)

func TestDetermineType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		res  model.Result
		want output.ResultType
	}{
		{
			name: "crossDomainRedirect",
			res: model.Result{
				Target: "https://a.example.com",
				Chain: []model.Hop{
					{Status: http.StatusFound, URL: "https://a.example.com/start"},
					{Status: http.StatusOK, URL: "https://other.com/home"},
				},
			},
			want: output.ResultTypeRedirect,
		},
		{
			name: "selfDomainRedirect302To200",
			res: model.Result{
				Target: "https://www.example.com",
				Chain: []model.Hop{
					{Status: http.StatusFound, URL: "https://www.example.com/go"},
					{Status: http.StatusOK, URL: "https://example.com/welcome"},
				},
			},
			want: output.ResultTypeUnredirect,
		},
		{
			name: "selfDomainRedirect301To200",
			res: model.Result{
				Target: "https://www.example.com",
				Chain: []model.Hop{
					{Status: http.StatusMovedPermanently, URL: "https://www.example.com/go"},
					{Status: http.StatusOK, URL: "https://example.com/welcome"},
				},
			},
			want: output.ResultTypeUnredirect,
		},
		{
			name: "directOk",
			res: model.Result{
				Target: "https://example.com",
				Chain: []model.Hop{
					{Status: http.StatusOK, URL: "https://example.com"},
				},
			},
			want: output.ResultTypeOK,
		},
		{
			name: "errorStatus",
			res: model.Result{
				Target: "https://example.com/missing",
				Chain: []model.Hop{
					{Status: http.StatusNotFound, URL: "https://example.com/missing"},
				},
			},
			want: output.ResultTypeError,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := output.DetermineType(tt.res); got != tt.want {
				t.Fatalf("DetermineType() = %v, want %v", got, tt.want)
			}
		})
	}
}
