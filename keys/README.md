# keys/

The root of trust for this Warden instance.

- **`warden-curator.pub`** — the curator's Ed25519 **public** key (hex). Safe to
  commit and to share. The node *pins* this key and will only expose skills
  signed by it. Agents verify against it.
- **`curator.seed`** — the curator's 32-byte **private** seed (hex).
  **NEVER commit this. Never share it.** It is `.gitignore`d. Anyone holding it
  can sign skills as the curator. Generate it locally with `warden keygen`.

Rotating the curator identity (`warden keygen --force`) invalidates every
existing signature — every skill must be re-signed, and the new public key
re-pinned by every agent. That is by design: trust is anchored to a key you
control, not to a name.

> This reference build stores the seed as a hex file for portability. A
> production curator should keep the seed in an HSM, a hardware key, or an OS
> keychain, and sign offline.
