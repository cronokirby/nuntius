# Client

The identity table stores the principle key used to identify a user,
and to testify to their identity. In practice, this is an Ed25519 key.

```
CREATE TABLE identity (
  public BLOB PRIMARY KEY NOT NULL,
  private BLOB NOT NULL
);
```
