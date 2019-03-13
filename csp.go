package csp

import (
	"bytes"
	"fmt"
	"strings"
)

// Constants for valid CSP strings.
const (
	// Directives
	DefaultSrc   = "default-src"
	ScriptSrc    = "script-src"
	ObjectSrc    = "object-src"
	StyleSrc     = "style-src"
	ImgSrc       = "img-src"
	MediaSrc     = "media-src"
	FrameSrc     = "frame-src"
	FontSrc      = "font-src"
	ConnectSrc   = "connect-src"
	FormAction   = "form-action"
	Sandbox      = "sandbox"
	ScriptNonce  = "script-nonce"
	PluginTypes  = "plugin-types"
	ReflectedXSS = "reflected-xss"
	ReportURI    = "report-uri"

	// Resource types
	None         = "'none'"
	Self         = "'self'"
	UnsafeInline = "'unsafe-inline'"
	UnsafeEval   = "'unsafe-eval'"
	Data         = "data:"
	HTTP         = "http:"
	HTTPS        = "https:"

	// Header is the header name. Use HeaderReportOnly to not block behavior
	// and instead report to a URI.
	Header           = "Content-Security-Policy"
	HeaderReportOnly = "Content-Security-Policy-Report-Only"

	// Delimiter is the string used to separate multiple directives.
	Delimiter = "; "
)

var (
	// Directives are a list of valid directives.
	Directives = []string{
		DefaultSrc,
		ScriptSrc,
		ObjectSrc,
		StyleSrc,
		ImgSrc,
		MediaSrc,
		FrameSrc,
		FontSrc,
		ConnectSrc,
		FormAction,
		Sandbox,
		ScriptNonce,
		PluginTypes,
		ReflectedXSS,
		ReportURI,
	}
)

// DirectivesMap is a map of directives to a list of resources/resource types.
type DirectivesMap map[string][]string

// Policy is a struct containing the data necessary to build a policy string.
type Policy struct {
	Directives DirectivesMap
}

// NewPolicy returns a new Policy.
func NewPolicy(p *Policy) *Policy {
	if p != nil {
		return p
	}

	return &Policy{
		Directives: DirectivesMap{},
	}
}

// Set overrides a directive with a list of resources/resource types.
func (p *Policy) Set(directive string, values []string) error {
	if err := validateDirective(directive); err != nil {
		return err
	}
	p.Directives[directive] = values
	return nil
}

// Add adds a single resource/resource type to a directive.
func (p *Policy) Add(directive string, values ...string) error {
	if err := validateDirective(directive); err != nil {
		return err
	}
	if _, ok := p.Directives[directive]; !ok {
		p.Directives[directive] = []string{}
	}

	for _, value := range values {
		p.Directives[directive] = append(p.Directives[directive], value)
	}
	return nil
}

// String returns a string representation of the policy, to be used in the
// header.
func (p *Policy) String() string {
	var b bytes.Buffer
	for _, d := range Directives {
		values, ok := p.Directives[d]
		if ok {
			b.WriteString(d + " ")
			b.WriteString(strings.Join(values, " "))
			b.WriteString(Delimiter)
		}
	}
	return strings.TrimSuffix(b.String(), Delimiter)
}

func validateDirective(directive string) error {
	for _, d := range Directives {
		if directive == d {
			return nil
		}
	}
	return fmt.Errorf("invalid CSP directive: %q", directive)
}
