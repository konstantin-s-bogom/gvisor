// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Binary staticpie changes a PIE that has the entry point of package
// //pkg/staticpie into a static PIE.
//
// Usage: staticpie <input> <output>
//
// See //pkg/staticpie for more information.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <input> <output>\n", os.Args[0])
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "staticpie: %v\n", err)
		os.Exit(1)
	}
	if err := convert(data); err != nil {
		fmt.Fprintf(os.Stderr, "staticpie: %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[2], data, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "staticpie: %v\n", err)
		os.Exit(1)
	}
}
