# Pull Request Summary

Provide a concise description of the changes introduced by this Pull Request.

## Type of Change

- [ ] `fix`: Bug fix (non-breaking change fixing an issue)
- [ ] `feat`: New feature (non-breaking change adding functionality)
- [ ] `feat!`: Breaking change (fix or feature that breaks backwards compatibility)
- [ ] `docs`: Documentation updates
- [ ] `chore`: Maintenance, configuration, or dependency updates

## DevSecOps Checklist

- [ ] All commits are **cryptographically signed using GPG** (`git commit -S -m "..."`).
- [ ] Package manager standards enforced: **100% `pnpm` used** (no `npm` or `npx`).
- [ ] Code formatted and linted cleanly via Biome (`pnpm run lint`).
- [ ] Vitest unit test suite passes cleanly (`pnpm run test`).
- [ ] Zero PII policy respected (no credentials, real tokens, or personal identifiers in code or tests).
- [ ] Documentation updated to reflect changes (if applicable).
