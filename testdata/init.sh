#!/bin/sh

vault policy write my-policy my-policy.hcl

vault kv put -mount=secret blah something=nothing
vault kv put -mount=secret db-secret user=admin pass=NotSecure
vault kv put -mount=secret my-secret password=Password123 key=a1b2c3

vault token create -policy=my-policy
