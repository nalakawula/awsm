# AWS Secret Manager Tool (awsm)

A command-line tool for managing AWS Secrets and injecting them as environment variables when running applications. It supports both AWS Secrets Manager and Parameter Store.

## Features

- Add, update, delete, and list secrets
- Support for both AWS Secrets Manager and Parameter Store
- Inject secrets as environment variables when running applications
- Validation for AWS service limits (4KB for Parameter Store, 64KB for Secrets Manager)
- Smart handling of JSON secrets with automatic merging of existing values during updates
- Support for multiple input formats:
  - JSON objects
  - Key-value pairs (key1=value1,key2=value2)
  - File contents (JSON or .env using @file syntax)

## Use Case

This tool is designed to securely store `.env` files in AWS Secrets Manager or AWS SSM Parameter Store. These secrets can then be seamlessly injected into applications using the `awsm run -name foo -type ps -- node server.js` command.

Additionally, the `-value` argument supports `.env` files, allowing you to easily import them. For example: `awsm add -name foo -type ps -value @/path/to/.env`.

## Installation

```bash
go install github.com/nalakawula/awsm@latest
```

## Usage

```
AWS Secret Manager Tool (awsm)

Usage:
  awsm add    [-type sm|ps] -name NAME -value VALUE [-desc DESCRIPTION]    Add a new secret
  awsm update [-type sm|ps] -name NAME -value VALUE [-desc DESCRIPTION]    Update an existing secret
  awsm delete [-type sm|ps] -name NAME                                     Delete a secret
  awsm list   [-type sm|ps]                                                List all secrets
  awsm get    [-type sm|ps] -name NAME [-format json|raw]                  Get a secret's value
  awsm run    [-type sm|ps] -name NAME -- COMMAND [ARGS...]                Run a command with secrets as env vars
  awsm help                                                                Show this help message

Options:
  -type    Service type: sm (Secrets Manager, default) or ps (Parameter Store)
  -name    Secret name
  -value   Secret value (JSON, key=value format, or a file with @/path/to/file containing JSON or .env)
           All values are stored as JSON objects
  -format  Output format for get command: json (default, pretty-prints JSON) or raw (plain text)
  -desc    Description for the secret or parameter (optional)

Notes:
  - All secrets are stored as JSON.
  - When updating, existing JSON keys will be preserved and new keys will be added or updated
  - When using the run command, each key in the JSON becomes an environment variable

Limitations:
  - Parameter Store: 4KB size limit
  - Secrets Manager: 64KB size limit
```

## Examples

### Add a new secret to AWS Secrets Manager

```bash
awsm add -name my-app/production/db -value '{"username":"admin","password":"secret123"}'
```

### Add a secret to Parameter Store

```bash
awsm add -type ps -name /my-app/production/api-key -value "abcdef123456"
```

### Add a secret using key-value format

```bash
awsm add -name my-app/config -value "db_host=localhost,db_port=5432,db_name=myapp"
```

### Load secret value from a file

```bash
awsm add -name my-app/credentials -value @/path/to/credentials.json
```

### Add a secret with description

```bash
awsm add -name my-app/auth -value '{"api_key":"abc123"}' -desc "Authentication credentials"
```

### Update an existing JSON secret (merges with existing values)

```bash
awsm update -name my-app/production/db -value '{"password":"newpassword123"}'
```

### List all secrets

```bash
awsm list
```

### List only Parameter Store secrets

```bash
awsm list -type ps
```

### Get a secret from Secrets Manager (default)
```bash
awsm get -name my-secret
```

### Get a secret from Parameter Store
```bash
awsm get -type ps -name my-secret
```

### Get a secret with raw output (no pretty printing)
```bash
awsm get -name my-secret -format raw
```

### Run an application with secrets as environment variables

```bash
awsm run -name my-app/production/db -- node server.js
```

This will inject the secret values as environment variables and run `node server.js`. If the secret contains JSON, each key becomes an environment variable (e.g., `USERNAME=admin` and `PASSWORD=secret123`).

## AWS Credentials

The tool uses the AWS SDK default credential chain. You can configure credentials in several ways:

- Environment variables
- AWS credentials file
- IAM roles for Amazon EC2
- IAM roles for ECS tasks

## Limitations

- Parameter Store: 4KB size limit
- Secrets Manager: 64KB size limit
