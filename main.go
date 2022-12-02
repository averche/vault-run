package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/hashicorp/vault-client-go"

	"golang.org/x/exp/slices"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <your-app>", os.Args[0])
	}

	ctx := context.Background()

	client, err := vault.New(
		vault.FromEnv,
		vault.WithBaseAddress("http://localhost:8200"),
	)
	if err != nil {
		log.Fatal(err)
	}

	permitted, err := acl(ctx, client)
	if err != nil {
		log.Fatal(err)
	}

	if err = populateEnvironment(ctx, client, permitted); err != nil {
		log.Fatal(err)
	}

	cmd := exec.CommandContext(ctx, os.Args[1])
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err = cmd.Run(); err != nil {
		log.Fatal(err)
	}
}

func acl(ctx context.Context, client *vault.Client) ([]string, error) {
	resp, err := client.Read(ctx, "/sys/internal/ui/resultant-acl")
	if err != nil {
		return nil, fmt.Errorf("resultant-acl: %w", err)
	}

	p, ok := resp.Data["exact_paths"]
	if !ok {
		return nil, fmt.Errorf("exact_paths key: missing")
	}

	acl, ok := p.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("exact_paths key: incorrect type")
	}

	var result []string

	for k, v := range acl {
		if strings.HasPrefix(k, "sys/") || strings.HasPrefix(k, "auth/") {
			continue
		}

		policy, ok := v.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("policy: incorrect type")
		}

		c, ok := policy["capabilities"]
		if !ok {
			return nil, fmt.Errorf("capabilities: missing")
		}

		capabilities, ok := c.([]interface{})
		if !ok {
			return nil, fmt.Errorf("capabilities: incorrect type")
		}

		capabilitiesStr, err := toStrings(capabilities)
		if err != nil {
			return nil, err
		}

		if !slices.Contains(capabilitiesStr, "read") {
			continue
		}

		result = append(result, k)
	}

	return result, nil
}

func populateEnvironment(ctx context.Context, client *vault.Client, permitted []string) error {
	// helper
	prefix := func(path string) string {
		parts := strings.FieldsFunc(strings.ToUpper(path), func(r rune) bool {
			return r == '/' || r == '-'
		})

		if len(parts) != 0 && parts[0] == "SECRET" {
			parts = parts[1:]
		}

		if len(parts) != 0 && parts[0] == "DATA" {
			parts = parts[1:]
		}

		return fmt.Sprintf("VAULT_%s", strings.Join(parts, "_"))
	}

	// set environment variables for each secret found in permitted slice
	for _, path := range permitted {
		resp, err := client.Read(ctx, path)

		if vault.IsErrorStatus(err, http.StatusNotFound) {
			continue
		} else if err != nil {
			return fmt.Errorf("error reading secret: %s: %w", path, err)
		}

		prefix := prefix(path)

		data, ok := resp.Data["data"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("unexpected secret format")
		}

		// set environment variables for each key in data
		for k, v := range data {
			secret, ok := v.(string)
			if !ok {
				return fmt.Errorf("unexpected secret format")
			}
			os.Setenv(fmt.Sprintf("%s_%s", prefix, strings.ToUpper(k)), secret)

			// log.Println(fmt.Sprintf("%s_%s", prefix, strings.ToUpper(k)), "=", secret)
		}
	}

	return nil
}

func toStrings(slice []interface{}) ([]string, error) {
	stings := make([]string, 0, len(slice))

	for _, e := range slice {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("%v is not a string: %T", e, e)
		}
		stings = append(stings, s)
	}

	return stings, nil
}
