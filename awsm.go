// Package main provides a CLI tool for managing secrets in AWS Secrets Manager and Parameter Store
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"golang.org/x/exp/maps"
)

const (
	// Size limits for AWS services
	parameterStoreSizeLimit = 4 * 1024  // 4KB maximum size for Parameter Store values
	secretManagerSizeLimit  = 64 * 1024 // 64KB maximum size for Secrets Manager values

	// Service types
	serviceTypeSecretsManager = "sm" // Short identifier for Secrets Manager
	serviceTypeParameterStore = "ps" // Short identifier for Parameter Store
)

// AWSMClient handles interactions with both Secrets Manager and Parameter Store services
type AWSMClient struct {
	smClient *secretsmanager.Client // AWS Secrets Manager client
	psClient *ssm.Client            // AWS Systems Manager Parameter Store client
	ctx      context.Context        // Context for AWS API calls
}

// newAWSMClient creates and initializes a new AWSMClient with AWS SDK configuration
func newAWSMClient(ctx context.Context) (*AWSMClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	return &AWSMClient{
		smClient: secretsmanager.NewFromConfig(cfg),
		psClient: ssm.NewFromConfig(cfg),
		ctx:      ctx,
	}, nil
}

// SecretData represents the common structure for a secret's content and metadata
type SecretData struct {
	Name        string // The name/identifier of the secret
	Value       string // The actual secret value
	Description string // Optional description of the secret
	ServiceType string // Which AWS service this secret belongs to (sm or ps)
	IsJSON      bool   // Whether the value is in JSON format
}

// commandOptions defines the common command line options for all commands
type commandOptions struct {
	serviceType *string       // Which service to use (sm or ps)
	name        *string       // Name of the secret
	value       *string       // Value of the secret (for add/update)
	description *string       // Description for the secret (optional)
	format      *string       // Output format for get command
	flagSet     *flag.FlagSet // FlagSet for parsing command line arguments
}

// parseCommonFlags sets up and parses common command line flags based on the command
// It returns the parsed options, any remaining arguments (after -- for run command),
// and any error that occurred during parsing
func parseCommonFlags(cmd string, args []string) (*commandOptions, []string, error) {
	opts := &commandOptions{
		flagSet: flag.NewFlagSet(cmd, flag.ExitOnError),
	}

	opts.serviceType = opts.flagSet.String("type", serviceTypeSecretsManager, "Service type: sm (Secrets Manager) or ps (Parameter Store)")
	opts.name = opts.flagSet.String("name", "", "Secret name")

	// Only add these flags for commands that need them
	switch cmd {
	case "add", "update":
		opts.value = opts.flagSet.String("value", "", "Secret value")
		opts.description = opts.flagSet.String("desc", "", "Secret description")
	case "get":
		opts.format = opts.flagSet.String("format", "json", "Output format: json or raw")
	}

	// Find the -- separator for run command
	cmdIndex := -1
	for i, arg := range args {
		if arg == "--" {
			cmdIndex = i
			break
		}
	}

	var cmdArgs []string
	if cmdIndex != -1 {
		// Split the args at the -- separator
		cmdArgs = args[cmdIndex+1:]
		if err := opts.flagSet.Parse(args[:cmdIndex]); err != nil {
			return nil, nil, err
		}
	} else {
		// No separator found, parse all args as flags
		if err := opts.flagSet.Parse(args); err != nil {
			return nil, nil, err
		}
		cmdArgs = []string{}
	}

	return opts, cmdArgs, nil
}

// parseValueAsJSON tries to parse the input value as JSON or as key=value pairs
// Returns the parsed value, a boolean indicating if it's JSON, and any error
// Values starting with @ are treated as filenames to read from
func parseValueAsJSON(value string) (string, bool, error) {
	// Check if we need to read from file (value starts with @)
	if strings.HasPrefix(value, "@") {
		filename := strings.TrimPrefix(value, "@")
		data, err := os.ReadFile(filename)
		if err != nil {
			return "", false, fmt.Errorf("failed to read file %s: %w", filename, err)
		}
		value = strings.TrimSpace(string(data))
	}

	// Check if it's already valid JSON
	var jsonObj any
	if err := json.Unmarshal([]byte(value), &jsonObj); err == nil {
		if _, ok := jsonObj.(map[string]any); ok {
			return value, true, nil
		}
	}

	// Parse key=value format
	if strings.Contains(value, "=") {
		jsonMap := make(map[string]string)

		// Handle multiple key=value pairs separated by commas
		if strings.Contains(value, ",") {
			for _, pair := range strings.Split(value, ",") {
				pair = strings.TrimSpace(pair)
				if pair == "" {
					continue
				}

				parts := strings.SplitN(pair, "=", 2)
				if len(parts) == 2 && parts[0] != "" {
					jsonMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				} else {
					fmt.Fprintf(os.Stderr, "Warning: Ignoring invalid key-value pair: %s\n", pair)
				}
			}
		} else {
			// Single key=value format
			parts := strings.SplitN(value, "=", 2)
			if len(parts) == 2 && parts[0] != "" {
				jsonMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		if len(jsonMap) > 0 {
			jsonBytes, err := json.Marshal(jsonMap)
			if err == nil {
				return string(jsonBytes), true, nil
			}
		}
	}

	// Not JSON, return original
	return value, false, nil
}

// validateSize checks if the value size is within the limits for the given service type
// Returns an error if the value exceeds size limits for the specified service
func validateSize(value string, serviceType string) error {
	valueSize := len([]byte(value))

	switch serviceType {
	case serviceTypeParameterStore:
		if valueSize > parameterStoreSizeLimit {
			return fmt.Errorf("parameter store value exceeds the 4KB limit (current size: %d bytes)", valueSize)
		}
	case serviceTypeSecretsManager:
		if valueSize > secretManagerSizeLimit {
			return fmt.Errorf("secrets manager value exceeds the 64KB limit (current size: %d bytes)", valueSize)
		}
	}

	return nil
}

// getExistingSecret retrieves an existing secret from either Secrets Manager or Parameter Store
// Returns the secret value, a boolean indicating if it exists, and any error
func (c *AWSMClient) getExistingSecret(name string, serviceType string) (string, bool, error) {
	switch serviceType {
	case serviceTypeParameterStore:
		output, err := c.psClient.GetParameter(c.ctx, &ssm.GetParameterInput{
			Name:           &name,
			WithDecryption: aws.Bool(true), // Always decrypt secure strings
		})
		if err != nil {
			return "", false, err
		}
		return *output.Parameter.Value, true, nil
	default: // serviceTypeSecretsManager
		output, err := c.smClient.GetSecretValue(c.ctx, &secretsmanager.GetSecretValueInput{
			SecretId: &name,
		})
		if err != nil {
			return "", false, err
		}
		return *output.SecretString, true, nil
	}
}

// mergeJSONValues merges new JSON values with existing ones
// Preserves existing keys that aren't in the new values, and updates those that are
func mergeJSONValues(existingValue, newValue string) (string, error) {
	var existingValues, newValues map[string]any

	if err := json.Unmarshal([]byte(existingValue), &existingValues); err != nil {
		return newValue, nil // If existing value isn't valid JSON, just use new value
	}

	if err := json.Unmarshal([]byte(newValue), &newValues); err != nil {
		return "", fmt.Errorf("failed to parse new values as JSON: %w", err)
	}

	// Using maps.Copy to merge new values into existing map
	maps.Copy(existingValues, newValues)

	// Convert back to JSON
	mergedJSON, err := json.Marshal(existingValues)
	if err != nil {
		return "", fmt.Errorf("failed to merge values: %w", err)
	}

	return string(mergedJSON), nil
}

// addSecret creates a new secret in either Secrets Manager or Parameter Store
// Parses the value as JSON or key=value pairs if possible
func (c *AWSMClient) addSecret(args []string) error {
	opts, _, err := parseCommonFlags("add", args)
	if err != nil {
		return err
	}

	if *opts.name == "" || *opts.value == "" {
		return fmt.Errorf("name and value are required")
	}

	// Parse and validate the value
	parsedValue, isJSON, err := parseValueAsJSON(*opts.value)
	if err != nil {
		return err
	}

	// Validate size
	if err := validateSize(parsedValue, *opts.serviceType); err != nil {
		return err
	}

	// Check if the secret already exists
	_, exists, _ := c.getExistingSecret(*opts.name, *opts.serviceType)
	if exists {
		return fmt.Errorf("secret/parameter '%s' already exists. Use update command to modify it", *opts.name)
	}

	// Save to the appropriate service
	switch *opts.serviceType {
	case serviceTypeParameterStore:
		paramInput := &ssm.PutParameterInput{
			Name:      opts.name,
			Value:     &parsedValue,
			Type:      ssmtypes.ParameterTypeSecureString, // Always use secure string for secrets
			Overwrite: aws.Bool(false),                    // Don't overwrite existing parameters
		}

		if *opts.description != "" {
			paramInput.Description = opts.description
		}

		_, err = c.psClient.PutParameter(c.ctx, paramInput)
		if err != nil {
			return fmt.Errorf("failed to save parameter: %w", err)
		}

		jsonPrefix := ""
		if isJSON {
			jsonPrefix = "JSON "
		}
		fmt.Printf("%sparameter '%s' saved successfully in Parameter Store\n", jsonPrefix, *opts.name)
	default: // serviceTypeSecretsManager
		secretInput := &secretsmanager.CreateSecretInput{
			Name:         opts.name,
			SecretString: &parsedValue,
		}

		if *opts.description != "" {
			secretInput.Description = opts.description
		}

		_, err = c.smClient.CreateSecret(c.ctx, secretInput)
		if err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}

		jsonPrefix := ""
		if isJSON {
			jsonPrefix = "JSON "
		}
		fmt.Printf("%ssecret '%s' created successfully in Secrets Manager\n", jsonPrefix, *opts.name)
	}

	return nil
}

// updateSecret updates an existing secret in either Secrets Manager or Parameter Store
// For JSON values, it merges the new values with existing ones
func (c *AWSMClient) updateSecret(args []string) error {
	opts, _, err := parseCommonFlags("update", args)
	if err != nil {
		return err
	}

	if *opts.name == "" || *opts.value == "" {
		return fmt.Errorf("name and value are required")
	}

	// Parse the input value
	parsedValue, isJSON, err := parseValueAsJSON(*opts.value)
	if err != nil {
		return err
	}

	// Get existing secret if it exists
	existingValue, exists, err := c.getExistingSecret(*opts.name, *opts.serviceType)
	if !exists {
		return fmt.Errorf("secret/parameter '%s' does not exist", *opts.name)
	}

	// For JSON values, attempt to merge them
	if isJSON {
		parsedValue, err = mergeJSONValues(existingValue, parsedValue)
		if err != nil {
			return err
		}
	}

	// Validate size
	if err := validateSize(parsedValue, *opts.serviceType); err != nil {
		return err
	}

	// Update in the appropriate service
	switch *opts.serviceType {
	case serviceTypeParameterStore:
		paramInput := &ssm.PutParameterInput{
			Name:      opts.name,
			Value:     &parsedValue,
			Type:      ssmtypes.ParameterTypeSecureString,
			Overwrite: aws.Bool(true), // Overwrite the existing parameter
		}

		if *opts.description != "" {
			paramInput.Description = opts.description
		}

		_, err = c.psClient.PutParameter(c.ctx, paramInput)
		if err != nil {
			return fmt.Errorf("failed to update parameter: %w", err)
		}

		fmt.Printf("Parameter '%s' updated successfully in Parameter Store\n", *opts.name)
	default: // serviceTypeSecretsManager
		updateInput := &secretsmanager.UpdateSecretInput{
			SecretId:     opts.name,
			SecretString: &parsedValue,
		}

		if *opts.description != "" {
			updateInput.Description = opts.description
		}

		_, err = c.smClient.UpdateSecret(c.ctx, updateInput)
		if err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}

		fmt.Printf("Secret '%s' updated successfully in Secrets Manager\n", *opts.name)
	}

	return nil
}

// deleteSecret removes a secret from either Secrets Manager or Parameter Store
func (c *AWSMClient) deleteSecret(args []string) error {
	opts, _, err := parseCommonFlags("delete", args)
	if err != nil {
		return err
	}

	if *opts.name == "" {
		return fmt.Errorf("name is required")
	}

	switch *opts.serviceType {
	case serviceTypeParameterStore:
		_, err := c.psClient.DeleteParameter(c.ctx, &ssm.DeleteParameterInput{
			Name: opts.name,
		})
		if err != nil {
			if strings.Contains(err.Error(), "ParameterNotFound") {
				return fmt.Errorf("parameter '%s' does not exist in Parameter Store", *opts.name)
			}
			return fmt.Errorf("failed to delete parameter: %w", err)
		}
		fmt.Printf("Parameter '%s' deleted successfully from Parameter Store\n", *opts.name)
	default: // serviceTypeSecretsManager
		_, err := c.smClient.DeleteSecret(c.ctx, &secretsmanager.DeleteSecretInput{
			SecretId: opts.name,
		})
		if err != nil {
			if strings.Contains(err.Error(), "ResourceNotFoundException") {
				return fmt.Errorf("secret '%s' does not exist in Secrets Manager", *opts.name)
			}
			return fmt.Errorf("failed to delete secret: %w", err)
		}
		fmt.Printf("Secret '%s' deleted successfully from Secrets Manager\n", *opts.name)
	}

	return nil
}

// listSecrets lists all secrets in Secrets Manager and/or Parameter Store
// If a service type is specified, only lists secrets from that service
func (c *AWSMClient) listSecrets(args []string) error {
	opts, _, err := parseCommonFlags("list", args)
	if err != nil {
		return err
	}

	// List Parameter Store secrets if requested
	if *opts.serviceType == serviceTypeParameterStore || *opts.serviceType == "" {
		fmt.Println("Parameter Store secrets:")
		params, err := c.psClient.DescribeParameters(c.ctx, &ssm.DescribeParametersInput{
			ParameterFilters: []ssmtypes.ParameterStringFilter{
				{
					Key:    aws.String("Type"),
					Option: aws.String("Equals"),
					Values: []string{"SecureString"}, // Only show secure strings (secrets)
				},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to list parameters: %w", err)
		}

		for _, param := range params.Parameters {
			fmt.Printf("  - %s\n", *param.Name)
		}
		fmt.Println()
	}

	// List Secrets Manager secrets if requested
	if *opts.serviceType == serviceTypeSecretsManager || *opts.serviceType == "" {
		fmt.Println("Secrets Manager secrets:")
		secrets, err := c.smClient.ListSecrets(c.ctx, &secretsmanager.ListSecretsInput{})
		if err != nil {
			return fmt.Errorf("failed to list secrets: %w", err)
		}

		for _, secret := range secrets.SecretList {
			fmt.Printf("  - %s\n", *secret.Name)
		}
	}

	return nil
}

// getSecret retrieves and displays a secret's value from either service
// Can display in raw or pretty-printed JSON format
func (c *AWSMClient) getSecret(args []string) error {
	opts, _, err := parseCommonFlags("get", args)
	if err != nil {
		return err
	}

	if *opts.name == "" {
		return fmt.Errorf("name is required")
	}

	secretValue, exists, err := c.getExistingSecret(*opts.name, *opts.serviceType)
	if !exists {
		if *opts.serviceType == serviceTypeParameterStore {
			return fmt.Errorf("parameter '%s' not found", *opts.name)
		}
		return fmt.Errorf("secret '%s' not found", *opts.name)
	}

	if err != nil {
		return err
	}

	// Output formatting
	switch *opts.format {
	case "json":
		// Try to parse as JSON and pretty print
		var jsonData any
		if err = json.Unmarshal([]byte(secretValue), &jsonData); err == nil {
			prettyJSON, err := json.MarshalIndent(jsonData, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to format JSON: %w", err)
			}
			fmt.Println(string(prettyJSON))
		} else {
			// Not JSON, just print as-is
			fmt.Println(secretValue)
		}
	default:
		// Raw format, just print as-is
		fmt.Println(secretValue)
	}

	return nil
}

// runWithSecrets executes a command with secrets loaded as environment variables
// For JSON secrets, each key becomes an environment variable
// For plain text secrets, the secret name is used as the variable name
func (c *AWSMClient) runWithSecrets(args []string) error {
	opts, cmdArgs, err := parseCommonFlags("run", args)
	if err != nil {
		return err
	}

	if *opts.name == "" {
		return fmt.Errorf("name is required")
	}

	if len(cmdArgs) == 0 {
		return fmt.Errorf("command to run is required after --")
	}

	secretValue, exists, err := c.getExistingSecret(*opts.name, *opts.serviceType)
	if !exists || err != nil {
		if *opts.serviceType == serviceTypeParameterStore {
			return fmt.Errorf("parameter not found in Parameter Store: %w", err)
		}
		return fmt.Errorf("secret not found in Secrets Manager: %w", err)
	}

	// Prepare environment for the command
	env := os.Environ()

	// Check if the secret is JSON
	var secretValues map[string]string
	isJSON := json.Unmarshal([]byte(secretValue), &secretValues) == nil

	if isJSON {
		// For JSON secrets, set each key as an environment variable
		for k, v := range secretValues {
			env = append(env, fmt.Sprintf("%s=%s", strings.ToUpper(k), v))
		}
	} else {
		// For non-JSON secrets, use the secret name as the variable name
		// Transforms paths like "/aws/service/name" to "SERVICE_NAME"
		varName := strings.ToUpper(strings.Replace(
			strings.TrimPrefix(
				strings.TrimPrefix(*opts.name, "/"),
				"aws/"),
			"/", "_", -1))
		env = append(env, fmt.Sprintf("%s=%s", varName, secretValue))
	}

	// Execute the command with the enhanced environment
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}

// printUsage displays detailed help information for all commands
func printUsage() {
	fmt.Print(`AWS Secret Manager Tool (awsm)

Usage:
  awsm add [-type sm|ps] -name NAME -value VALUE [-desc DESCRIPTION]    Add a new secret
  awsm update [-type sm|ps] -name NAME -value VALUE [-desc DESCRIPTION] Update an existing secret
  awsm delete [-type sm|ps] -name NAME              Delete a secret
  awsm get [-type sm|ps] -name NAME [-format json|raw] Get a secret's value
  awsm list [-type sm|ps]                           List all secrets
  awsm run [-type sm|ps] -name NAME -- COMMAND [ARGS...]    Run a command with secrets as env vars
  awsm help                                         Show this help message

Options:
  -type    Service type: sm (Secrets Manager, default) or ps (Parameter Store)
  -name    Secret name
  -value   Secret value (string, JSON, key-value pairs like "key1=val1,key2=val2", or @file to read from file)
  -format  Output format for get command: json (default, pretty-prints JSON) or raw (plain text)
  -desc    Description for the secret or parameter (optional)

Notes:
  - When updating JSON secrets, existing keys will be updated and new keys will be appended automatically
`)
}

// main is the entry point for the CLI application
func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	ctx := context.Background()
	client, err := newAWSMClient(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing AWS client: %v\n", err)
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:] // All arguments after the command

	var cmdErr error
	switch command {
	case "add":
		cmdErr = client.addSecret(args)
	case "update":
		cmdErr = client.updateSecret(args)
	case "delete":
		cmdErr = client.deleteSecret(args)
	case "list":
		cmdErr = client.listSecrets(args)
	case "get":
		cmdErr = client.getSecret(args)
	case "run":
		cmdErr = client.runWithSecrets(args)
	case "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}

	if cmdErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", cmdErr)
		os.Exit(1)
	}
}
