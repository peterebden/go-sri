Subresource Integrity checking for Go
=====================================

[![Go Report Card](https://goreportcard.com/badge/github.com/peterebden/go-sri)](https://goreportcard.com/report/github.com/peterebden/go-sri) [![GoDoc](https://godoc.org/github.com/peterebden/go-sri?status.svg)](https://godoc.org/github.com/peterebden/go-sri)

go-sri implements [Subresource Integrity](https://www.w3.org/TR/SRI/) checking for Go. It can parse SRI strings and
validate content against them; this is done efficiently, calculating only the set of hashes that are useful
for an input.

See [godoc](https://godoc.org/github.com/peterebden/go-sri) for more information & usage.
