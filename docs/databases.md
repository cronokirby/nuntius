# Client

The identity table stores the principle key used to identify a user,
and to testify to their identity. In practice, this is an Ed25519 key.

```
CREATE TABLE identity (
  id BOOLEAN PRIMARY KEY CONSTRAINT one_row CHECK (id) NOT NULL,
  public BLOB NOT NULL,
  private BLOB NOT NULL
);
```

The friend table stores names for known identity keys.

```
CREATE TABLE friend (
  public BLOB PRIMARY KEY NOT NULL,
  name TEXT NOT NULL
);
```

The pre-key table stores the full pre-keys we've registered with the server:

```
CREATE TABLE prekey (
  public BLOB PRIMARY KEY NOT NULL,
  private BLOB NOT NULL
);
```

# Server

The pre-key table stores signed pre-keys for each identity.

```
CREATE TABLE prekey (
  identity BLOB PRIMARY KEY NOT NULL,
  prekey BLOB NOT NULL,
  signature BLOB NOT NULL
);
```
