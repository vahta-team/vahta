# Sharing a vault with a team

A vault is shared by sending a file through a chat (Telegram, Slack, Discord).
There is no server and no git. The design assumes the chat is **untrusted,
permanent storage that gets forwarded**: whatever you send there stays there.
So each person gets their own file holding only their own secrets, a member's
key is protected by their own password, and the owner checks who is on the other
end with six words read out over another channel.

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

A member cannot reveal or copy a value, remove a secret, change rules, or hold a
session. Everything else is the owner's.

## Step by step

**1. The new member makes an identity** (once per machine):

```
vahta id
```

A window asks for a password. It prints a key (`vh1...`) and six words.
`vahta id --show` prints them again without a password.

**2. The member sends the key to the owner in the chat.** The key is public:
sending it in the open is fine. The member then reads the **six words to the
owner over a call or in person, not in the chat**. This is not optional (see
"Why the words").

**3. The owner adds the member:**

```
vahta members add ann --role runner --key vh1... --for 30d
```

A window shows the name, role and end date and asks the owner to *type* the six
words the member read out. A mismatch refuses the add and writes nothing. Then
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
chat and reads ann the **owner's six words** (printed by `share`, and by
`vahta members words`).

**6. The member installs it** in their project folder:

```
vahta join ann.vhp
```

The first time, a window shows the owner's six words; the member confirms they
match what the owner said. That is when the owner's key is pinned on this
machine. After that, `vahta run --secret OPENAI_API_KEY -- ...` works as usual,
with the identity password asked in the window.

**7. Changes.** After a `grant`, `revoke`, `extend` or a new secret, the owner
runs `vahta share` again and sends the new file; the member runs `vahta join`
again. A package that is not newer than the one installed is refused, so an old
file from the chat cannot roll a member back.

**8. An editor sends a secret to the owner** (no merging of whole files):

```
vahta add MY_TOKEN                     # in the editor's package
vahta share --to owner MY_TOKEN -o my_token.vhp
```

The owner runs `vahta join my_token.vhp` in the project. A window names the
secret and the sender and asks; on approval it is imported. A new secret has no
approved rules until the owner adds them with `vahta bind`, and the sender
keeps access to it.

**9. Ending access.** `vahta members extend ann --for 30d` moves the end date.
`vahta members remove ann` removes ann, re-keys what ann held, and **prints the
secrets to rotate** in the real services. `vahta revoke SECRET ann` does the same
for one secret. `vahta members list` shows each member, role, end date, state
and which secrets they hold.

## Why the words

The chat is where an attacker would swap a member's key for their own, so the
owner would be adding the attacker. The words are derived from the key (72 bits),
so a swapped key has different words. They are read out over a second channel
the attacker does not control. In the other direction, the owner's words stop a
forged package: without them a stranger could send a "package" signed with their
own key. If the words differ, stop and ask in person.

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
  including the programs and folders they name (paths from the owner's
  machine).
- **Members do not hold sessions.** Each `vahta run` asks for the identity
  password.
- **A forgotten identity password cannot be recovered.** The owner adds a new
  identity (a new key and new words) and removes the old member.
- **One thing to know about editors.** An editor who changes a secret in their
  package locally raises its generation; the owner's next package may then be
  "not newer". The owner should import the editor's secrets first, then share.
- **The owner re-keying the vault** (after a lost device) changes the owner
  key; a member's `join` then refuses the new package until the member is told
  (this version does not follow an owner key change on `join`).
