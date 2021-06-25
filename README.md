# Nuntius

This is just an attempt to have fun by implementing a Signal-esque E2E messaging app.

Right now this is just a little CLI application to communicate with another person
through an intermediate server. Although communication is E2E encrypted,
atm everything is session based, unlike the more asynchronous models supported by
other apps like Signal.

# Usage

Here's an overview of the different commands that exist:

```
Usage: nuntius <command>

Flags:
  -h, --help               Show context-sensitive help.
      --database=STRING    Path to local database.

Commands:
  generate
    Generate a new identity pair.

  identity
    Fetch the current identity.

  add-friend <name> <pub>
    Add a new friend

  server [<port>]
    Start a server.

  chat <url> <name>
    Chat with a friend.

Run "nuntius <command> --help" for more information on a command.
```

All the commands take an optional path to a database, in order to save data
like keys and friend names, and things like that.

The basic idea is that you generate your key pair with `generate`.
You then share your identity key (which you can check with `identity`)
with people you want to communicate with. You can associate other people's
identities with a name through the `add-friend` command. Finally, you can
start a communication session with friends using the `chat` command.
A server is needed to forward messages, and store prekeys, but
won't be able to inspect any of your communication. A server can be
run with `server`.

## Generate

```
Usage: nuntius generate

Generate a new identity pair.

Flags:
  -h, --help               Show context-sensitive help.
      --database=STRING    Path to local database.

      --force              Overwrite existing identity
```

This generates a new key pair, printing out the public identity key.
This identity key is then used to establish communication with you later.

## Identity

```
Usage: nuntius identity

Fetch the current identity.

Flags:
  -h, --help               Show context-sensitive help.
      --database=STRING    Path to local database.
```

This command is useful to see what your public identity key is.

## Add Friend

```
Usage: nuntius add-friend <name> <pub>

Add a new friend

Arguments:
  <name>    The name of the friend
  <pub>     Their public identity key

Flags:
  -h, --help               Show context-sensitive help.
      --database=STRING    Path to local database.
```

Instead of chatting using just an identity key, instead you first
associate an identity key with a name, and use that to identify
a user instead.

## Chatting

```
Usage: nuntius chat <url> <name>

Chat with a friend.

Arguments:
  <url>     The URL used to access this server
  <name>    The name of the friend to chat with

Flags:
  -h, --help               Show context-sensitive help.
      --database=STRING    Path to local database.
```

This is used to start a new communication session with another user.
After both ends have established the session, they can send text messages
just by typing in the console.

This needs a server to forward messages, and the url for the server (no trailing `/`).

## Server

```
Usage: nuntius server [<port>]

Start a server.

Arguments:
  [<port>]    The port to use

Flags:
  -h, --help               Show context-sensitive help.
      --database=STRING    Path to local database.
```

To run a relay server, you can use this command. This will take a port
to listen on.
