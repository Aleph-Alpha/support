# Contributing

Thank you for contributing to this repository. This project supports internal operations and tooling. Please follow the guidelines below so changes stay consistent, secure, and safe to share across the team.

## Before You Start

- Open an issue or discuss significant changes with a repository maintainer before starting large or structural work.
- Keep changes focused. Prefer small, reviewable pull requests over large mixed changes.
- Match existing naming, layout, and conventions in the area you are editing.

## Customer and Client Confidentiality

**Do not include customer or client names anywhere in this repository.**

This applies to all content, including but not limited to:

- Documentation and markdown files
- Pull request titles, descriptions, and comments
- Commit messages and branch names
- Scripts, configuration, logs, and example data
- File and directory names
- Issue titles and descriptions

Use neutral placeholders instead, for example:

- Generic descriptions such as "production customer environment" or "staging deployment"

If you are unsure whether something identifies a customer, treat it as identifying information and redact or generalize it.

If customer-related details are required for a task, keep them outside this repository in approved internal systems and reference only non-identifying context here.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/): `<type>[scope]: <description>`

Examples: `feat(backup): add restore helper`, `fix(k8s): correct port-forward script`, `docs: add contributing guide`

## Pull Requests

- Describe what changed and why.
- Link related issues when applicable.

## Documentation

- Prefer concise, actionable documentation.
- Use placeholders for environment-specific values.

## Security

- Never commit secrets, credentials, private keys, or `.env` files.
- If sensitive data was committed by mistake, notify a repository maintainer immediately so it can be rotated and removed properly.
- Review your diff before opening a pull request.
