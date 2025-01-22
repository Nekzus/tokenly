# Contributing to Tokenly

First off, thanks for taking the time to contribute! 🎉

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Pull Requests](#pull-requests)
- [Development Setup](#development-setup)
- [Commit Guidelines](#commit-guidelines)
- [Project Structure](#project-structure)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior through GitHub issues.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* Use a clear and descriptive title
* Describe the exact steps which reproduce the problem
* Provide specific examples to demonstrate the steps
* Describe the behavior you observed after following the steps
* Explain which behavior you expected to see instead and why
* Include code samples and error messages if applicable
* Specify the version of Tokenly you're using
* Include your Node.js version and operating system

### Suggesting Features

Before creating feature suggestions, please check the issue list as you might find out that you don't need to create one. When you are creating a feature suggestion, please include as many details as possible:

* Use a clear and descriptive title
* Provide a step-by-step description of the suggested feature
* Provide specific examples to demonstrate the steps
* Describe the current behavior and explain which behavior you expected to see instead
* Explain why this feature would be useful to most Tokenly users

### Pull Requests

Please follow these steps to have your contribution considered:

1. Follow the [commit guidelines](#commit-guidelines)
2. Follow the [coding standards](#coding-standards)
3. Update documentation as needed
4. Add tests if applicable
5. Make sure all tests pass
6. Update TypeScript types if necessary

## Development Setup

1. Fork and clone the repository
2. Install dependencies:
```bash
npm install
```

3. Run tests:
```bash
npm test
```

4. Build the project:
```bash
npm run build
```

## Commit Guidelines

We use [Conventional Commits](https://www.conventionalcommits.org/) and [semantic-release](https://semantic-release.gitbook.io/semantic-release/) for automated versioning and changelog generation. This means your commits must follow the specified format:

### Commit Message Format
Each commit message consists of a **header**, a **body** and a **footer**. The header has a special format that includes a **type** and a **subject**:

```
<type>: <subject>
<BLANK LINE>
<body>
<BLANK LINE>
<footer>
```

### Types
* **feat**: A new feature
* **fix**: A bug fix
* **docs**: Documentation only changes
* **style**: Changes that do not affect the meaning of the code
* **refactor**: A code change that neither fixes a bug nor adds a feature
* **perf**: A code change that improves performance
* **test**: Adding missing tests or correcting existing tests
* **chore**: Changes to the build process or auxiliary tools
* **security**: Security-related changes

Example:
```
feat: add token rotation functionality

Implement automatic token rotation with configurable intervals.
Includes rotation scheduling and token refresh handling.

Closes #123
```

## Project Structure

```
tokenly/
├── src/                # Source code
│   ├── utils/         # Utility functions
│   │   ├── ipHelper.ts    # IP address utilities
│   │   └── errorHandler.ts # Error handling
│   ├── types.ts       # TypeScript type definitions
│   └── index.ts       # Main entry point
├── tests/             # Test files
├── docs/              # Documentation
│   ├── api/          # API reference
│   └── guide/        # User guide
└── examples/          # Example implementations
```

### Coding Standards

- Use TypeScript with strict mode enabled
- Follow the existing code style (ESLint configuration)
- Write meaningful variable and function names
- Add JSDoc comments for public APIs
- Keep functions small and focused
- Write unit tests for new features
- Maintain 100% type safety

### Testing

- Write tests for new features
- Update tests for bug fixes
- Ensure all tests pass:
```bash
npm test
```
- Maintain test coverage above 90%

### Documentation

- Update README.md for significant changes
- Add JSDoc comments for new functions
- Update API documentation in docs/api/
- Update guides in docs/guide/ if needed
- Include examples for new features
- Update TypeScript types documentation

## Questions?

Feel free to:
- Open an issue for questions
- Start a discussion in the GitHub repository
- Check existing issues and discussions for answers

Thank you for contributing to Tokenly! 🚀 