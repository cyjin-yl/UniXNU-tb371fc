// SPDX-License-Identifier: MIT
// Minimal front end to the pinned ipsw ranged file extractor.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"os"
	"strings"
)

func main() {
	url := flag.String("url", "", "Official HTTPS IPSW URL")
	output := flag.String("output", "", "Destination directory")
	device := flag.String("device", "j820ap", "Product type or board")
	pattern := flag.String("pattern", "^/?(sbin/launchd|usr/lib/dyld)$", "Anchored file pattern")
	dmg := flag.String("dmg", "fs", "Filesystem image selector")
	flag.Parse()
	if !strings.HasPrefix(*url, "https://") || *output == "" {
		fmt.Fprintln(os.Stderr, "--url HTTPS and --output are required")
		os.Exit(2)
	}
	config := &extract.Config{
		URL: *url, Output: *output, KernelDevice: *device,
		Pattern: *pattern, DMGs: true, Ranged: true, RangedDMG: *dmg,
		JSON: true, Insecure: false,
	}
	paths, err := extract.Search(config)
	result := map[string]any{"schema_version": 1, "complete": err == nil, "artifacts": paths}
	if err != nil {
		result["error"] = err.Error()
	}
	if e := json.NewEncoder(os.Stdout).Encode(result); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
