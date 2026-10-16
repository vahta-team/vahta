# Sharing a vault with a team

A vault is shared by sending a file through a chat (Telegram, Slack, Discord).
There is no server and no git. The design assumes the chat is **untrusted,
permanent storage that gets forwarded**: whatever you send there stays there.
So each person gets their own file holding only their own secrets, a member's
key is protected by their own password, and the owner checks who is on the other
end with digits read out over another channel.

This is for small teams (5 to 15 people). The owner is whoever created the
vault.

## What each person has

- The **owner** has the vault (`.vahta/vault.vht`) and its password, and adds
  and removes members.
- A **member** has an *identity* (`identity.vht` in their Vahta data directory,
  sealed with their own password) and a *package* the owner sent them, installed
  as `.vahta/vault.vht` in their project folder.

Roles:

| Role   | Can |
|--------|-----|
| runner | run commands with the secrets it was given (`vahta run`, `vahta http`) |
| editor | also add and change its own secrets, and send one to the owner |
| admin  | as an editor here (a package holds no other members, so there is nobody for an admin to manage) |

A member cannot reveal or copy a value, remove a secret or change rules. Its
sessions only run commands (step 9). Everything else is the owner's.

## Step by step

**1. The new member makes an identity** (once per machine):

```
vahta id
```

A window asks for a password. It prints a key (`vh1...`) and a verification code: six groups of four digits (`4821 3905 ...`).
`vahta id --show` prints them again without a password.

**2. The member sends the key to the owner in the chat.** The key is public:
sending it in the open is fine. The member then reads the **digits to the
owner over a call or in person, not in the chat**. This is not optional (see
"Why the digits").

**3. The owner adds the member:**

```
vahta members add ann --role runner --key vh1... --for 30d
```

A window shows the name, role and end date and asks the owner to *type* the
digits the member read out (spaces, dashes or nothing between the groups are
all fine). A mismatch refuses the add and writes nothing. Then
the owner's password. Access lasts 30 days unless `--for` says otherwise
(`--for never` means no end).

**4. The owner gives the member only the secrets they need:**

```
vahta grant OPENAI_API_KEY ann
```

**5. The owner makes the member's package and sends it:**

```
vahta share ann -o ann.vhp
```

`ann.vhp` holds only ann's entry and the secrets ann holds: no other secret's
name or ciphertext, no other member, no device. The owner sends it to ann in the
chat and reads ann the **owner's digits** (printed by `share`, and by
`vahta members digits`).

**6. The member installs it** in their project folder:

```
vahta join ann.vhp
```

The first time, a window shows the owner's digits; the member confirms they
match what the owner said. That is when the owner's key is pinned on this
machine. After that, `vahta run --secret OPENAI_API_KEY -- ...` works as usual,
with the identity password asked in the window.

**7. Changes.** After a `grant`, `revoke`, `extend` or a new secret, the owner
runs `vahta share` again and sends the new file; the member runs `vahta join`
again. A package is compared by the **owner's generation**, a counter the owner signs
into it. A package that is not newer than the one installed is refused, so an old
file from the chat cannot roll a member back. An editor's own local changes do
not move that counter, so they never make the owner's next package look old; but
installing a package replaces the editor's file, and the window lists any secret
only the old file had (send those to the owner first).

**8. An editor sends a secret to the owner** (no merging of whole files):

```
vahta add MY_TOKEN                     # in the editor's package
vahta share --to owner MY_TOKEN -o my_token.vhp
```

The owner runs `vahta join my_token.vhp` in the project. A window names the
secret and the sender and asks; on approval it is imported. A new secret has no
approved rules until the owner adds them with `vahta bind`, and the sender
keeps access to it.

The editor may **propose rules** for a new secret, with the words of `vahta bind`:

```
vahta share --to owner MY_TOKEN -o my_token.vhp --allow "python3 lib/x.py" --net none
```

The proposal travels in the signed file as text. The owner's window shows it in
plain words ("In effect, if you approve them: ...", with the programs it resolves
to here and any warnings) and offers *Import with these rules*, *Import without
rules* or *Cancel*. Only on approval are the rules built on the owner's machine
and signed into the vault, exactly as a `vahta bind` approval; without it the
secret arrives with no rules. An editor cannot change or remove the rules of a
secret the owner already has (a proposal for one is ignored); only the owner does,
and the owner's rules reach editors and runners in the next package.

Each transfer carries a counter, one above the editor's last, signed by the
editor. The owner records the highest counter imported from each editor in the
vault, so an old file is refused whatever either clock says.

**9. Sessions.** A member can run `vahta unlock` (identity password) to run
commands without a window for each one. A member's session is the same as anyone's
(run and http only, never reveal or copy), and it ends no later than the
membership: its length is the shorter of what was asked and the time left, and it
is not offered an extension.

**10. Ending access.** `vahta members extend ann --for 30d` moves the end date.
`vahta members remove ann` removes ann, re-keys what ann held, and **prints the
secrets to rotate** in the real services. `vahta revoke SECRET ann` does the same
for one secret. `vahta members list` shows each member, role, end date, state
and which secrets they hold.

## Why the digits

The chat is where an attacker would swap a member's key for their own, so the
owner would be adding the attacker. The digits are derived from the key (about 79 bits),
so a swapped key has different digits. They are digits, not words, so people read
them aloud in their own language. They are read out over a second channel
the attacker does not control. In the other direction, the owner's digits stop a
forged package: without them a stranger could send a "package" signed with their
own key. If the digits differ, stop and ask in person.

## What this does not do

Be honest about the limits.

- **A malicious member keeps what they were given.** A member holds a key and
  can decrypt their own secrets with their own code. Vahta stops their agent from
  reading values by accident and keeps values out of the chat; it does not stop
  a person who wants to copy a secret they are allowed to run.
- **Old packages stay in the chat history.** Anyone who gets that history, now
  or in five years, and has the member's identity file and password, can open
  the old package. Expiry is checked by the member's own software: a member who
  patches it out can still open an old file.
- **Real revocation is changing the value at the service.** `remove` and
  `revoke` re-key the vault, so new packages do not carry the old value, but
  cannot take back what was already read. That is why Vahta prints what to
  rotate. Do it.
- **Give the minimum, and short expiries.** Grant only the secrets a person
  needs, prefer runner to editor, use the default 30 days or less, and send a
  fresh package each time it is extended.
- **The owner's machine is the root.** The owner's password protects everyone's
  secrets. Packages the owner sends carry the rules the owner approved,
  including the programs and folders they name. A place inside the project is
  stored relative to it (`$PROJECT/lib/x.py`) and expanded from the member's own
  project folder, so it matches there and does not show the owner's layout. A
  place outside the project (`/usr/bin/python3`) stays as approved and may not
  exist on the member's machine; `share` lists those by secret name. Rules made
  before this are written relative in the package, too.
- **A forgotten identity password cannot be recovered.** The owner adds a new
  identity (a new key and new digits) and removes the old member.
- **The owner re-keying the vault** (after a lost device) changes the owner key.
  The new package carries the vault's chain of successor records, each signed by
  the key before it. `vahta join` accepts a new owner key only if that chain leads
  from the key pinned on the member's machine (a chain of at most four re-keys),
  and only after the member confirms the new owner digits with the owner. A
  package signed by any other key is refused.
