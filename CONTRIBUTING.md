# Contributing to BugHunter AI

Thanks for your interest in contributing! Here's how to get started.

## Ways to Contribute

### New Agents
Create a new `.md` file in `skills/BugBountyFramework/Agents/`. Follow the pattern of existing agents:
- Frontmatter with `name`, `role`, `persona`
- Clear phase structure
- Specific techniques and payloads
- Finding format JSON
- Anti-patterns section

### New Tools
TypeScript tools go in `skills/BugBountyFramework/Tools/`. Requirements:
- Use `#!/usr/bin/env bun` shebang
- Use `parseArgs` from `"util"` for CLI arguments
- Export key functions for use by other tools
- Include `--help` usage information

### Bug Fixes
- Open an issue first to discuss
- Include reproduction steps
- PR with fix + description of what changed

### Documentation
- Better examples and sample prompts
- Translations
- Video walkthroughs

## Development Setup

```bash
git clone https://github.com/h4ckologic/PiRanha.git
cd PiRanha
./install.sh
```

## Pull Request Process

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/new-agent`
3. Make your changes
4. Test with a real target (your own, or a sanctioned bug bounty program)
5. Submit PR with clear description

## Code Style

- TypeScript for tools (Bun runtime)
- Markdown for agents and documentation
- Keep agents focused — one vulnerability class per agent
- Hypothesis-driven, not tool-driven

## Responsible Disclosure

If you find a security issue in BugHunter AI itself (not in targets you're testing), please report it privately via GitHub Security Advisories rather than opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
