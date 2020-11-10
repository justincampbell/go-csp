// Package csp provides a sane interface for building Content-Security-Policy header values.
//
// Content-Security-Policy
//
// From Wikipedia: Content Security Policy is a computer security standard introduced to prevent cross-site scripting, clickjacking and other code injection attacks resulting from execution of malicious content in the trusted web page context.
//
// https://en.wikipedia.org/wiki/Content_Security_Policy
//
// https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
//
// Recommendations
//
// - Build your policy at boot and store the final string in a variable to be used for each request, instead of recomputing each time.
//
// - Always begin with an empty policy, and run your web server/deploy your code to a test environment to see which requests are blocked by a browser. Then, one by one, add resources to directives until you have no errors.
//
package csp
