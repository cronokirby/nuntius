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