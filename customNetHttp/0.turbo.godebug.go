/*
Turbo - A cross-platform, high-performance HTTP web server with a real-time, visual management interface. Manage unlimited domains and multi-level wildcard subdomains, SSL certificates, URI rewrites, request preprocessing, fine-grained request rate and size limiting, as well as custom aliases, headers, MIMEs, and indexes.
Copyright (C) 2026 OKZGN

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please visit one of the following:
- https://okzgn.com/#contact
- https://okzgn.github.io/#contact
*/

package customNetHttp

// Substitute for internal/godebug, which can't be imported outside Go's
// tree. customNetHttp doesn't read GODEBUG: every setting is "" and Go's
// code applies its default behaviour (that of go 1.26 in go.mod).
//
// customNetHttp/regenerate turns each godebug.X of Go's code into
// godebug_X.

type godebug_Setting struct {
	name string
}

func godebug_New(name string) *godebug_Setting {
	return &godebug_Setting{name: name}
}

func (s *godebug_Setting) Name() string {
	if s.name != "" && s.name[0] == '#' {
		return s.name[1:]
	}
	return s.name
}

func (s *godebug_Setting) Value() string { return "" }

func (s *godebug_Setting) IncNonDefault() {}

func (s *godebug_Setting) String() string { return s.Name() + "=" }
