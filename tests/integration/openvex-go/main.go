// Check that the official Go implementation parses and accepts Vexcalibur output.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	openvex "github.com/openvex/go-vex/pkg/vex"
	packageurl "github.com/package-url/packageurl-go"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: openvexcompat OPENVEX_JSON")
		os.Exit(2)
	}

	contents, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail("read OpenVEX fixture", err)
	}

	var document openvex.VEX
	if err := json.Unmarshal(contents, &document); err != nil {
		fail("parse OpenVEX fixture", err)
	}
	if document.Context != openvex.ContextLocator() {
		fail("check OpenVEX context", fmt.Errorf("got %q, want %q", document.Context, openvex.ContextLocator()))
	}
	if len(document.Statements) == 0 {
		fail("check statements", fmt.Errorf("document contains no statements"))
	}

	for statementIndex := range document.Statements {
		statement := &document.Statements[statementIndex]
		if err := statement.Validate(); err != nil {
			fail(fmt.Sprintf("validate statement %d", statementIndex), err)
		}
		if len(statement.Products) == 0 {
			fail(fmt.Sprintf("check statement %d products", statementIndex), fmt.Errorf("statement contains no products"))
		}
		for productIndex := range statement.Products {
			product := &statement.Products[productIndex]
			purl, ok := product.Identifiers[openvex.PURL]
			if !ok || purl == "" {
				fail(fmt.Sprintf("check statement %d product %d", statementIndex, productIndex), fmt.Errorf("product has no PURL identifier"))
			}
			if product.ID != purl {
				fail(fmt.Sprintf("check statement %d product %d", statementIndex, productIndex), fmt.Errorf("product ID %q differs from PURL %q", product.ID, purl))
			}
			parsedPURL, err := packageurl.FromString(purl)
			if err != nil {
				fail(fmt.Sprintf("check statement %d product %d", statementIndex, productIndex), fmt.Errorf("parse product PURL %q: %w", purl, err))
			}
			if parsedPURL.Version == "" {
				fail(fmt.Sprintf("check statement %d product %d", statementIndex, productIndex), fmt.Errorf("product PURL %q has no version", purl))
			}
			if !statement.MatchesProduct(purl, "") {
				fail(fmt.Sprintf("match statement %d product %d", statementIndex, productIndex), fmt.Errorf("official matcher rejected %q", purl))
			}
		}
	}
}

func fail(operation string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}
