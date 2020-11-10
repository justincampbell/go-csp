package csp_test

import (
	"fmt"

	csp "github.com/justincampbell/go-csp"
)

func Example() {
	// Create a new policy
	policy := csp.NewPolicy(&csp.Policy{
		Directives: csp.DirectivesMap{
			// You can pass initial values here for each directive
			csp.DefaultSrc: []string{csp.Self},
			csp.ImgSrc:     []string{csp.Self, csp.Data, csp.HTTPS},
		},
	})

	// Use Add() to add resources to a directive

	// Bootstrap
	policy.Add(csp.FontSrc, "https://maxcdn.bootstrapcdn.com")
	policy.Add(csp.StyleSrc, "https://maxcdn.bootstrapcdn.com")

	// Google Fonts
	policy.Add(csp.FontSrc, "https://fonts.googleapis.com")
	policy.Add(csp.FontSrc, "https://fonts.gstatic.com")
	policy.Add(csp.StyleSrc, "https://fonts.googleapis.com")

	// Use String() to render the built header value
	fmt.Printf(csp.Header + ": " + policy.String())

	// Output:
	// Content-Security-Policy: default-src 'self'; style-src https://maxcdn.bootstrapcdn.com https://fonts.googleapis.com; img-src 'self' data: https:; font-src https://maxcdn.bootstrapcdn.com https://fonts.googleapis.com https://fonts.gstatic.com
}
