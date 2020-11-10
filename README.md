# go-csp

[![GoDoc](https://godoc.org/github.com/justincampbell/go-csp?status.svg)](https://godoc.org/github.com/justincampbell/go-csp)

Go library for generating a [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) header, offering the following benefits:

* Allows grouping of directives for the same domain across separate types, making the header more maintainable.
* Ensures that added directives added are valid.
* Constants for directives and resource types reduce user error.

## Example

Try this out on [The Go Playground](https://play.golang.org/p/UGB1tZ8DwKq).

```go
import (
  "github.com/justincampbell/go-csp"
)

func buildCSPHeader() string {
	pol := csp.NewPolicy(&csp.Policy{
		Directives: csp.DirectivesMap{
			csp.DefaultSrc: []string{csp.Self},
			csp.ConnectSrc: []string{csp.Self},
			csp.FontSrc:    []string{csp.Self},
			csp.ImgSrc:     []string{csp.Self, csp.Data, csp.HTTPS},
			csp.ScriptSrc:  []string{csp.Self, csp.UnsafeInline},
			csp.StyleSrc:   []string{csp.Self, csp.UnsafeInline},
		},
	})

	// Bootstrap
	pol.Add(csp.FontSrc, "https://maxcdn.bootstrapcdn.com")
	pol.Add(csp.StyleSrc, "https://maxcdn.bootstrapcdn.com")

	// Google Analytics
	pol.Add(csp.ConnectSrc, "https://www.google-analytics.com")
	pol.Add(csp.ImgSrc, "https://www.google-analytics.com")
	pol.Add(csp.ScriptSrc, "https://www.google-analytics.com")

	// Google Tag Manager
	pol.Add(csp.ScriptSrc, "https://www.googletagmanager.com")

	// Google Fonts
	pol.Add(csp.FontSrc, "https://fonts.googleapis.com")
	pol.Add(csp.FontSrc, "https://fonts.gstatic.com")
	pol.Add(csp.StyleSrc, "https://fonts.googleapis.com")

	// TypeKit
	pol.Add(csp.FontSrc, "https://use.typekit.net")
	pol.Add(csp.StyleSrc, "https://p.typekit.net")
	pol.Add(csp.StyleSrc, "https://use.typekit.net")

	header := pol.String()

	log.Printf("[INFO] Built CSP header: %q", header)

	return header
}
```
