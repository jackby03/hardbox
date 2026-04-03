// Package main is the entrypoint for the hardbox Terraform provider.
// Build with: go build -o terraform-provider-hardbox .
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/jackby03/terraform-provider-hardbox/internal/provider"
)

// version is set at build time via ldflags:
//
//	-ldflags "-X main.version=v0.3.0"
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "Enable provider debug mode")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/jackby03/hardbox",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)
	if err != nil {
		log.Fatal(err)
	}
}
