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
)

const (
	// Size limits for AWS services
	parameterStoreSizeLimit = 4 * 1024  // 4KB
	secretManagerSizeLimit  = 64 * 1024 // 64KB

	// Service types
	serviceTypeSecretsManager = "sm"
	serviceTypeParameterStore = "ps"
)

type AWSMClient struct {
	smClient *secretsmanager.Client
	psClient *ssm.Client
}

func newAWSMClient() (*AWSMClient, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	return &AWSMClient{
		smClient: secretsmanager.NewFromConfig(cfg),
		psClient: ssm.NewFromConfig(cfg),
	}, nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	client, err := newAWSMClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing AWS client: %v\n", err)
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "add":
		err = client.addSecret(args)
	case "update":
		err = client.updateSecret(args)
	case "delete":
		err = client.deleteSecret(args)
	case "list":
		err = client.listSecrets(args)
	case "get":
		err = client.getSecret(args)
	case "run":
		err = client.runWithSecrets(args)
	case "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

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

// parseValueAsJSON tries to parse the input value as JSON or as key=value pairs
// and returns the value as a JSON string
func parseValueAsJSON(value string) (string, bool, error) {
	// Check if we need to read from file (value starts with @)
	if strings.HasPrefix(value, "@") {
		filename := strings.TrimPrefix(value, "@")
		data, err := os.ReadFile(filename)
		if err != nil {
			return "", false, fmt.Errorf("failed to read file %s: %w", filename, err)
		}
		value = string(data)
		// Trim any trailing newlines or whitespace from file content
		value = strings.TrimSpace(value)
	}

	// First, check if it's already valid JSON
	var jsonObj interface{}
	if err := json.Unmarshal([]byte(value), &jsonObj); err == nil {
		// Check if it's a JSON object/map
		if _, ok := jsonObj.(map[string]interface{}); ok {
			// Already valid JSON object
			return value, true, nil
		}
	}

	// Check if it contains multiple key=value pairs separated by commas
	if strings.Contains(value, ",") && strings.Contains(value, "=") {
		jsonMap := make(map[string]string)
		pairs := strings.Split(value, ",")
		for _, pair := range pairs {
			pair = strings.TrimSpace(pair) // Trim spaces around pairs
			if pair == "" {
				continue // Skip empty pairs
			}

			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 && parts[0] != "" {
				key := strings.TrimSpace(parts[0]) // Trim spaces around key
				val := strings.TrimSpace(parts[1]) // Trim spaces around value
				jsonMap[key] = val
			} else {
				// Invalid format, continue with processing other pairs
				fmt.Fprintf(os.Stderr, "Warning: Ignoring invalid key-value pair: %s\n", pair)
			}
		}

		if len(jsonMap) > 0 {
			// Convert to JSON
			jsonBytes, err := json.Marshal(jsonMap)
			if err == nil {
				return string(jsonBytes), true, nil
			}
		}
		// If we can't convert to JSON, return original
		return value, false, nil
	} else if strings.Contains(value, "=") {
		// Single key=value format
		parts := strings.SplitN(value, "=", 2)
		if len(parts) == 2 && parts[0] != "" {
			key := strings.TrimSpace(parts[0]) // Trim spaces around key
			val := strings.TrimSpace(parts[1]) // Trim spaces around value
			// Convert to JSON
			jsonMap := map[string]string{key: val}
			jsonBytes, err := json.Marshal(jsonMap)
			if err == nil {
				return string(jsonBytes), true, nil
			}
		}
	}

	// Not JSON, return original
	return value, false, nil
}

func (c *AWSMClient) addSecret(args []string) error {
	// Parse flags
	cmdFlags := flag.NewFlagSet("add", flag.ExitOnError)
	serviceType := cmdFlags.String("type", serviceTypeSecretsManager, "Service type: sm (Secrets Manager) or ps (Parameter Store)")
	name := cmdFlags.String("name", "", "Secret name")
	value := cmdFlags.String("value", "", "Secret value")
	description := cmdFlags.String("desc", "", "Secret description")

	if err := cmdFlags.Parse(args); err != nil {
		return err
	}

	if *name == "" || *value == "" {
		return fmt.Errorf("name and value are required")
	}

	// Try to parse the input as JSON, key=value pair, or file contents
	parsedValue, isJSON, err := parseValueAsJSON(*value)
	if err != nil {
		return err
	}
	*value = parsedValue

	// Validate size limits
	valueSize := len([]byte(*value))
	if *serviceType == serviceTypeParameterStore && valueSize > parameterStoreSizeLimit {
		return fmt.Errorf("parameter store value exceeds the 4KB limit (current size: %d bytes)", valueSize)
	} else if *serviceType == serviceTypeSecretsManager && valueSize > secretManagerSizeLimit {
		return fmt.Errorf("secrets manager value exceeds the 64KB limit (current size: %d bytes)", valueSize)
	}

	ctx := context.Background()

	if *serviceType == serviceTypeParameterStore {
		// Check if parameter already exists
		_, err := c.psClient.GetParameter(ctx, &ssm.GetParameterInput{
			Name: name,
		})
		if err == nil {
			return fmt.Errorf("parameter '%s' already exists in Parameter Store. Use update command to modify it", *name)
		}

		paramInput := &ssm.PutParameterInput{
			Name:      name,
			Value:     value,
			Type:      ssmtypes.ParameterTypeSecureString,
			Overwrite: aws.Bool(false),
		}

		// Add description if provided
		if *description != "" {
			paramInput.Description = description
		}

		_, err = c.psClient.PutParameter(ctx, paramInput)
		if err != nil {
			return fmt.Errorf("failed to save parameter: %w", err)
		}
		if isJSON {
			fmt.Printf("JSON parameter '%s' saved successfully in Parameter Store\n", *name)
		} else {
			fmt.Printf("Parameter '%s' saved successfully in Parameter Store\n", *name)
		}
	} else {
		// Check if secret already exists
		_, err := c.smClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: name,
		})
		if err == nil {
			return fmt.Errorf("secret '%s' already exists in Secrets Manager. Use update command to modify it", *name)
		}

		secretInput := &secretsmanager.CreateSecretInput{
			Name:         name,
			SecretString: value,
		}

		// Add description if provided
		if *description != "" {
			secretInput.Description = description
		}

		_, err = c.smClient.CreateSecret(ctx, secretInput)
		if err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}
		if isJSON {
			fmt.Printf("JSON secret '%s' created successfully in Secrets Manager\n", *name)
		} else {
			fmt.Printf("Secret '%s' created successfully in Secrets Manager\n", *name)
		}
	}

	return nil
}

func (c *AWSMClient) updateSecret(args []string) error {
	// Parse flags
	cmdFlags := flag.NewFlagSet("update", flag.ExitOnError)
	serviceType := cmdFlags.String("type", serviceTypeSecretsManager, "Service type: sm (Secrets Manager) or ps (Parameter Store)")
	name := cmdFlags.String("name", "", "Secret name")
	value := cmdFlags.String("value", "", "Secret value")
	description := cmdFlags.String("desc", "", "Secret description")

	if err := cmdFlags.Parse(args); err != nil {
		return err
	}

	if *name == "" || *value == "" {
		return fmt.Errorf("name and value are required")
	}

	// Try to parse the input as JSON, key=value pair, or file contents
	parsedValue, isJSON, err := parseValueAsJSON(*value)
	if err != nil {
		return err
	}
	*value = parsedValue

	ctx := context.Background()

	// If we have JSON input, try to handle it intelligently
	if isJSON {
		var existingSecretValue string
		var existingValues map[string]interface{}
		var newValues map[string]interface{}
		secretExists := false

		// Parse the new values
		if err := json.Unmarshal([]byte(*value), &newValues); err != nil {
			return fmt.Errorf("failed to parse new values as JSON: %w", err)
		}

		if *serviceType == serviceTypeParameterStore {
			// Try to get existing parameter
			psOutput, psErr := c.psClient.GetParameter(ctx, &ssm.GetParameterInput{
				Name:           name,
				WithDecryption: aws.Bool(true),
			})

			if psErr == nil {
				existingSecretValue = *psOutput.Parameter.Value
				secretExists = true
			}
		} else {
			// Try to get existing secret from Secrets Manager
			smOutput, smErr := c.smClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
				SecretId: name,
			})

			if smErr == nil {
				existingSecretValue = *smOutput.SecretString
				secretExists = true
			}
		}

		// If the secret exists and is JSON, merge the values
		if secretExists {
			// Try to parse existing value as JSON
			if err := json.Unmarshal([]byte(existingSecretValue), &existingValues); err == nil {
				// Merge the existing and new values
				for k, v := range newValues {
					existingValues[k] = v
				}

				// Convert back to JSON
				mergedJSON, err := json.Marshal(existingValues)
				if err != nil {
					return fmt.Errorf("failed to merge values: %w", err)
				}

				*value = string(mergedJSON)
			}
			// If existing value isn't JSON, just overwrite with new value
		}
	}

	// Validate size limits
	valueSize := len([]byte(*value))
	if *serviceType == serviceTypeParameterStore && valueSize > parameterStoreSizeLimit {
		return fmt.Errorf("parameter store value exceeds the 4KB limit (current size: %d bytes)", valueSize)
	} else if *serviceType == serviceTypeSecretsManager && valueSize > secretManagerSizeLimit {
		return fmt.Errorf("secrets manager value exceeds the 64KB limit (current size: %d bytes)", valueSize)
	}

	if *serviceType == serviceTypeParameterStore {
		// Check if parameter exists first
		_, getErr := c.psClient.GetParameter(ctx, &ssm.GetParameterInput{
			Name: name,
		})
		if getErr != nil {
			return fmt.Errorf("parameter '%s' does not exist in Parameter Store", *name)
		}

		paramInput := &ssm.PutParameterInput{
			Name:      name,
			Value:     value,
			Type:      ssmtypes.ParameterTypeSecureString,
			Overwrite: aws.Bool(true),
		}

		// Add description if provided
		if *description != "" {
			paramInput.Description = description
		}

		_, err := c.psClient.PutParameter(ctx, paramInput)
		if err != nil {
			return fmt.Errorf("failed to update parameter: %w", err)
		}

		fmt.Printf("Parameter '%s' updated successfully in Parameter Store\n", *name)
	} else {
		// Check if secret exists first
		_, getErr := c.smClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: name,
		})
		if getErr != nil {
			return fmt.Errorf("secret '%s' does not exist in Secrets Manager", *name)
		}

		updateInput := &secretsmanager.UpdateSecretInput{
			SecretId:     name,
			SecretString: value,
		}

		// Add description if provided
		if *description != "" {
			updateInput.Description = description
		}

		_, err = c.smClient.UpdateSecret(ctx, updateInput)
		if err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}

		fmt.Printf("Secret '%s' updated successfully in Secrets Manager\n", *name)
	}

	return nil
}

func (c *AWSMClient) deleteSecret(args []string) error {
	// Parse flags
	cmdFlags := flag.NewFlagSet("delete", flag.ExitOnError)
	serviceType := cmdFlags.String("type", serviceTypeSecretsManager, "Service type: sm (Secrets Manager) or ps (Parameter Store)")
	name := cmdFlags.String("name", "", "Secret name")

	if err := cmdFlags.Parse(args); err != nil {
		return err
	}

	if *name == "" {
		return fmt.Errorf("name is required")
	}

	ctx := context.Background()

	if *serviceType == serviceTypeParameterStore {
		_, err := c.psClient.DeleteParameter(ctx, &ssm.DeleteParameterInput{
			Name: name,
		})
		if err != nil {
			// Check for ParameterNotFound error
			if strings.Contains(err.Error(), "ParameterNotFound") {
				return fmt.Errorf("parameter '%s' does not exist in Parameter Store", *name)
			}
			return fmt.Errorf("failed to delete parameter: %w", err)
		}
		fmt.Printf("Parameter '%s' deleted successfully from Parameter Store\n", *name)
	} else {
		_, err := c.smClient.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
			SecretId: name,
		})
		if err != nil {
			// Check for ResourceNotFoundException error
			if strings.Contains(err.Error(), "ResourceNotFoundException") {
				return fmt.Errorf("secret '%s' does not exist in Secrets Manager", *name)
			}
			return fmt.Errorf("failed to delete secret: %w", err)
		}
		fmt.Printf("Secret '%s' deleted successfully from Secrets Manager\n", *name)
	}

	return nil
}

func (c *AWSMClient) listSecrets(args []string) error {
	// Parse flags
	cmdFlags := flag.NewFlagSet("list", flag.ExitOnError)
	serviceType := cmdFlags.String("type", "", "Service type: sm (Secrets Manager) or ps (Parameter Store)")

	if err := cmdFlags.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()

	if *serviceType == serviceTypeParameterStore || *serviceType == "" {
		fmt.Println("Parameter Store secrets:")
		params, err := c.psClient.DescribeParameters(ctx, &ssm.DescribeParametersInput{
			ParameterFilters: []ssmtypes.ParameterStringFilter{
				{
					Key:    aws.String("Type"),
					Option: aws.String("Equals"),
					Values: []string{"SecureString"},
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

	if *serviceType == serviceTypeSecretsManager || *serviceType == "" {
		fmt.Println("Secrets Manager secrets:")
		secrets, err := c.smClient.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
		if err != nil {
			return fmt.Errorf("failed to list secrets: %w", err)
		}

		for _, secret := range secrets.SecretList {
			fmt.Printf("  - %s\n", *secret.Name)
		}
	}

	return nil
}

func (c *AWSMClient) getSecret(args []string) error {
	// Parse flags
	cmdFlags := flag.NewFlagSet("get", flag.ExitOnError)
	serviceType := cmdFlags.String("type", serviceTypeSecretsManager, "Service type: sm (Secrets Manager) or ps (Parameter Store)")
	name := cmdFlags.String("name", "", "Secret name")
	format := cmdFlags.String("format", "json", "Output format: json or raw")

	if err := cmdFlags.Parse(args); err != nil {
		return err
	}

	if *name == "" {
		return fmt.Errorf("name is required")
	}

	ctx := context.Background()
	var secretValue string
	var err error

	if *serviceType == serviceTypeParameterStore {
		// Get from Parameter Store
		output, err := c.psClient.GetParameter(ctx, &ssm.GetParameterInput{
			Name:           name,
			WithDecryption: aws.Bool(true),
		})
		if err != nil {
			return fmt.Errorf("failed to get parameter: %w", err)
		}
		secretValue = *output.Parameter.Value
	} else {
		// Get from Secrets Manager
		output, err := c.smClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: name,
		})
		if err != nil {
			return fmt.Errorf("failed to get secret: %w", err)
		}
		secretValue = *output.SecretString
	}

	// Output formatting
	if *format == "json" {
		// Try to parse as JSON and pretty print
		var jsonData interface{}
		if err = json.Unmarshal([]byte(secretValue), &jsonData); err == nil {
			// It's valid JSON, pretty print it
			prettyJSON, err := json.MarshalIndent(jsonData, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to format JSON: %w", err)
			}
			fmt.Println(string(prettyJSON))
		} else {
			// Not JSON, just print as-is
			fmt.Println(secretValue)
		}
	} else {
		// Raw format, just print as-is
		fmt.Println(secretValue)
	}

	return nil
}

func (c *AWSMClient) runWithSecrets(args []string) error {
	// Parse flags
	cmdFlags := flag.NewFlagSet("run", flag.ExitOnError)
	serviceType := cmdFlags.String("type", serviceTypeSecretsManager, "Service type: sm (Secrets Manager) or ps (Parameter Store)")
	name := cmdFlags.String("name", "", "Secret name to inject as environment variables")

	// Find the index of "--" in args
	cmdIndex := -1
	for i, arg := range args {
		if arg == "--" {
			cmdIndex = i
			break
		}
	}

	var cmdArgs []string
	if cmdIndex != -1 {
		cmdArgs = args[cmdIndex+1:]
		if err := cmdFlags.Parse(args[:cmdIndex]); err != nil {
			return err
		}
	} else {
		if err := cmdFlags.Parse(args); err != nil {
			return err
		}
	}

	if *name == "" {
		return fmt.Errorf("name is required")
	}

	if cmdIndex == -1 || len(cmdArgs) == 0 {
		return fmt.Errorf("command to run is required after --")
	}

	ctx := context.Background()

	// Try to get the secret based on specified service type
	var secretValue string
	var isJSON bool
	var secretValues map[string]string

	if *serviceType == serviceTypeParameterStore {
		// Get from Parameter Store
		psOutput, psErr := c.psClient.GetParameter(ctx, &ssm.GetParameterInput{
			Name:           name,
			WithDecryption: aws.Bool(true),
		})

		if psErr != nil {
			return fmt.Errorf("parameter not found in Parameter Store: %w", psErr)
		}

		secretValue = *psOutput.Parameter.Value
		// Check if the parameter is a JSON object
		if err := json.Unmarshal([]byte(secretValue), &secretValues); err == nil {
			isJSON = true
		}
	} else {
		// Get from Secrets Manager
		smOutput, smErr := c.smClient.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: name,
		})

		if smErr != nil {
			return fmt.Errorf("secret not found in Secrets Manager: %w", smErr)
		}

		secretValue = *smOutput.SecretString
		// Check if the secret is a JSON object
		if err := json.Unmarshal([]byte(secretValue), &secretValues); err == nil {
			isJSON = true
		}
	}

	// Prepare environment for the command
	env := os.Environ()

	if isJSON {
		// For JSON secrets, set each key as an environment variable
		for k, v := range secretValues {
			env = append(env, fmt.Sprintf("%s=%s", strings.ToUpper(k), v))
		}
	} else {
		// For non-JSON secrets, use the secret name as the variable name
		varName := strings.ToUpper(strings.Replace(
			strings.TrimPrefix(
				strings.TrimPrefix(*name, "/"),
				"aws/"),
			"/", "_", -1))
		env = append(env, fmt.Sprintf("%s=%s", varName, secretValue))
	}

	// Execute the command
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	return cmd.Run()
}
