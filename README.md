# vault-run

## Installation

```shell-session
export GOPRIVATE=github.com/hashicorp/vault-client-go
go get github.com/averche/vault-run
```

## Usage

```shell-session
vault login
export VAULT_TOKEN=$(vault print token)
./vault-run ./my-app
```

This will start `./my-app` with all secrets populated as environment variables in the form `VAULT_PATH_TO_SECRET`

## Limitations

- does not currently work currently
- does not currently work with non-exact policy paths (should be easy to add)

