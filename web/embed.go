// Package web incorpora gli asset del frontend (dashboard.html).
package web

import "embed"

//go:embed dashboard.html
var Files embed.FS
