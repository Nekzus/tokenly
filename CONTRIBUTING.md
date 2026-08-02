# Contributing to Tokenly

Thank you for your interest in contributing to **Tokenly**! This document provides guidelines and commands to get started quickly while maintaining high code quality and security standards.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Package Manager Standard (100% pnpm)

This project strictly uses **`pnpm` (v10+)**. Do **NOT** use `npm` or `yarn`.

### Prerequisites

- Node.js 20.x or 22.x LTS
- `pnpm` 10.5.2+ (`corepack enable` or `npm install -g pnpm@10.5.2`)

### Local Setup

```bash
# Clone the repository
git clone https://github.com/Nekzus/tokenly.git
cd tokenly

# Install dependencies cleanly
pnpm install --frozen-lockfile
```

## Development Commands

All development tasks use `pnpm`:

```bash
# Run unit tests with Vitest
pnpm run test

# Run tests in watch mode
pnpm run test:watch

# Lint and format code with Biome
pnpm run lint
pnpm run format

# Build library artifacts (dist/)
pnpm run build

# Preview VitePress documentation locally
pnpm run docs:dev
```

## Mandatory GPG Commit Signing

All commits submitted to this repository **MUST be cryptographically signed using GPG**:

```bash
git commit -S -m "feat(auth): add fingerprinted token rotation support"
```

Verify local GPG configuration:
```bash
git config --global user.signingkey <YOUR_KEY_ID>
git config --global commit.gpgsign true
```

## Conventional Commits & SemVer

Commits must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

| Commit Type | SemVer Impact | Description |
| :--- | :--- | :--- |
| `fix(scope):` | **PATCH** (`1.5.4` -> `1.5.5`) | Bug fix |
| `feat(scope):` | **MINOR** (`1.5.4` -> `1.6.0`) | New feature |
| `feat(scope)!:` | **MAJOR** (`1.5.4` -> `2.0.0`) | Breaking change |
| `chore(scope):` | **No release** | Maintenance or configuration updates |
| `docs(scope):` | **No release** | Documentation updates |

## Branch Strategy

- **`main`**: Production stable branch (`@latest` tag on npmjs.com).
- **`beta`**: Feature-freeze pre-release testing branch (`@beta` tag on npmjs.com).
- **`alpha`**: Active experimental pre-release branch (`@alpha` tag on npmjs.com).
- **`feat/*` / `fix/*`**: Ephemeral feature branches for Pull Requests.