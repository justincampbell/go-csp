package csp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicy(t *testing.T) {
	tests := []struct {
		name           string
		policy         func() *Policy
		expectedString string
	}{
		{
			"empty",
			func() *Policy {
				return NewPolicy(nil)
			},
			``,
		},
		{
			"initial",
			func() *Policy {
				return NewPolicy(&Policy{
					Directives: DirectivesMap{
						DefaultSrc: []string{None},
					},
				})
			},
			`default-src 'none'`,
		},
		{
			"add",
			func() *Policy {
				pol := NewPolicy(nil)
				pol.Add(DefaultSrc, Self)
				pol.Add(DefaultSrc, UnsafeInline)
				return pol
			},
			`default-src 'self' 'unsafe-inline'`,
		},
		{
			"set",
			func() *Policy {
				pol := NewPolicy(nil)
				pol.Set(DefaultSrc, []string{Self})
				return pol
			},
			`default-src 'self'`,
		},
		{
			"multiple delimiter",
			func() *Policy {
				pol := NewPolicy(nil)
				pol.Set(DefaultSrc, []string{Self})
				pol.Add(MediaSrc, None)
				return pol
			},
			`default-src 'self'; media-src 'none'`,
		},
		{
			"example",
			func() *Policy {
				pol := NewPolicy(nil)
				pol.Set(DefaultSrc, []string{Self})
				pol.Add(ConnectSrc, Self, "https://www.google-analytics.com")
				pol.Add(ScriptSrc, Self, "https://www.google-analytics.com")
				return pol
			},
			`default-src 'self'; ` +
				`script-src 'self' https://www.google-analytics.com; ` +
				`connect-src 'self' https://www.google-analytics.com`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := tt.policy()
			assert.Equal(t, tt.expectedString, policy.String())
		})
	}
}
