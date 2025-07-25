# Contributing to Gateway

We love your input! We want to make contributing to Gateway as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

### Pull Requests

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

### Development Setup

```bash
# Clone your fork
git clone https://github.com/awesomeapibrasil/gateway.git
cd gateway

# Set up the development environment
./scripts/setup-dev.sh

# Build the project
cargo build

# Run tests
cargo test

# Run the gateway
cargo run -- --config config/gateway.yaml
```

### Code Style

We use the standard Rust formatting and linting tools:

```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Check documentation
cargo doc --no-deps
```

### Testing

Please ensure your code includes appropriate tests:

```bash
# Run all tests
cargo test

# Run specific test module
cargo test waf

# Run integration tests
cargo test --test integration

# Run benchmarks
cargo bench
```

### Documentation

- Update README.md for significant changes
- Add inline documentation for public APIs
- Update configuration examples if needed
- Add or update examples in the `docs/examples/` directory

## Bug Reports

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/awesomeapibrasil/gateway/issues/new).

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

### Bug Report Template

```markdown
## Summary
Brief description of the issue.

## Environment
- Gateway version:
- Operating System:
- Rust version:
- Configuration:

## Steps to Reproduce
1. First step
2. Second step
3. ...

## Expected Behavior
What should have happened.

## Actual Behavior
What actually happened.

## Additional Context
Any additional information that might help.
```

## Feature Requests

We love feature requests! Please [open an issue](https://github.com/awesomeapibrasil/gateway/issues/new) with:

- Clear description of the feature
- Motivation/use case
- Proposed implementation (if you have ideas)
- Potential alternatives

## Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

### Enforcement

Project maintainers have the right and responsibility to remove, edit, or reject comments, commits, code, wiki edits, issues, and other contributions that are not aligned to this Code of Conduct.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Getting Help

- Join our [GitHub Discussions](https://github.com/awesomeapibrasil/gateway/discussions)
- Check existing [issues](https://github.com/awesomeapibrasil/gateway/issues)
- Read the [documentation](docs/)

## Recognition

Contributors will be recognized in:
- The README.md file
- Release notes for significant contributions
- The project's contributors page

Thank you for contributing to Gateway! 🚀