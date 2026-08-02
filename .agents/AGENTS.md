# Workspace Agent Directives (tokenly)

## Strict Rule: Mandatory GPG Cryptographic Commit Signing

- **Absolute Requirement:** All commits made in this repository (by AI agents and human developers alike) **MUST be cryptographically signed using GPG** (`git commit -S -m "..."`).
- **GitHub Verification:** Every commit merged into `main`, `beta`, `alpha`, or submitted via Pull Request must display the **Verified** status on GitHub.

## Strict Rule: 100% pnpm Package Manager Enforcement

- **No npm / No npx:** Never run `npm` or `npx` commands in scripts, workflows, or terminal commands for this workspace. Always use `pnpm`, `pnpm exec`, or `pnpm dlx`.
- **Lockfile Integrity:** Never generate or commit `package-lock.json`. Only `pnpm-lock.yaml` is permitted.

## Strict Rule: English Documentation Standard

- All repository documentation (`README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.github/*`, code comments, commit messages) must be written in **ENGLISH ONLY**.
