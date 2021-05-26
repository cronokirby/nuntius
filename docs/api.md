Here we provide a description of the API used to interact with the server.

# Pre-Keys

This endpoint is used to register a new pre-key for a public identity.

`POST /prekey/{id}`

```
{
  "prekey": "<base64-x25519 key>",
  "sig": "<base64 signature>"
}
```

The signature should be verifiable using the identity key passed into
the end point. The identity key should be base64 encoded.
