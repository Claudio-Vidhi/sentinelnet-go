// Package web incorpora gli asset del frontend (dashboard.html e static/).
package web

import "embed"

//go:embed dashboard.html static/*
var Files embed.FS
