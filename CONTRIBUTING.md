# Contributing to MCPGuard-CLI

Thank you for your interest in contributing to MCPGuard-CLI! 🎉

## Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/MCPGuard-CLI.git`
3. Run tests: `python -m pytest tests/`

## How to Contribute

### Reporting Bugs
- Open a GitHub Issue with the bug description and reproduction steps
- Include the target you were scanning and the output/error message

### Submitting Fixes
1. Create a branch: `git checkout -b fix/your-fix-description`
2. Make your changes
3. Run tests: `python -m pytest tests/`
4. Commit: `git commit -m "fix: description of your fix"`
5. Push and open a Pull Request

### Adding New Scanners
1. Create a new scanner in `src/scanners/`
2. Extend `BaseScanner` class
3. Register it in `mcpguard.py`
4. Add tests in `tests/`
5. Open a Pull Request

## Code Style
- Follow PEP 8
- Add docstrings to all public functions and classes
- Keep zero external dependencies

## Pull Request Guidelines
- Keep PRs small and focused
- Include tests for new functionality
- Update documentation if needed
- Use conventional commit messages: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`
