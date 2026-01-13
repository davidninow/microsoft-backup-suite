# Contributing to Microsoft Personal Data Backup Suite

Thank you for your interest in contributing! This repository contains two tools (OneDrive Backup and OneNote Exporter), and we welcome contributions to either or both.

## 🎯 How to Contribute

### Reporting Bugs

If you find a bug in either tool:

1. **Check existing issues** - Someone may have already reported it
2. **Open a new issue** with:
   - Tool name (OneDrive Backup or OneNote Exporter)
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Your environment:
     - OS (Windows/Mac/Linux)
     - Python version
     - Account type (Personal/Work/School)
   - Error messages or logs
   - Screenshots if applicable

**Label your issue:** `bug`, `onedrive`, or `onenote`

### Suggesting Features

We love new ideas! To suggest a feature:

1. **Check roadmap** - It might already be planned (see main README.md)
2. **Open an issue** with label `enhancement`
3. **Describe:**
   - Which tool(s) it applies to
   - What problem it solves
   - How you envision it working
   - Any implementation ideas
   - Potential challenges

### Pull Requests

We actively welcome pull requests!

## 📋 Before You Start

### For All Contributions

1. **Check existing issues and PRs** - Avoid duplicates
2. **For major changes** - Open an issue first to discuss
3. **Test your changes** - With a real Microsoft account
4. **Follow code style** - Match existing patterns

### Tool-Specific Setup

#### OneDrive Backup
- Test with personal Microsoft accounts
- Verify with both local OneDrive and online login
- Test with various file types and sizes
- Check resume capability (interrupt and restart)

#### OneNote Exporter
- Test with personal Microsoft accounts
- Verify exports work with target apps (Joplin/Evernote)
- Test with various content types (images, audio, PDFs)
- Check folder structure preservation

## 🔧 Pull Request Process

### 1. Fork & Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/davidninow/microsoft-backup-suite.git
cd microsoft-backup-suite
```

### 2. Create a Branch

```bash
# For OneDrive features
git checkout -b onedrive/your-feature-name

# For OneNote features
git checkout -b onenote/your-feature-name

# For shared improvements
git checkout -b shared/your-feature-name
```

### 3. Make Your Changes

#### Code Guidelines

**Python Style:**
- Follow PEP 8 guidelines
- Use descriptive variable names
- Add docstrings to all functions
- Keep functions focused and single-purpose
- Use type hints where helpful

**Code Organization:**
- Keep related functionality together
- Extract complex logic into separate functions
- Add comments for non-obvious code
- Handle errors gracefully with try-except blocks

**Example:**
```python
def download_file(url: str, destination: Path) -> bool:
    """
    Download a file from Microsoft Graph API to local storage.
    
    Args:
        url: Direct download URL from Microsoft Graph API
        destination: Local path where file should be saved
        
    Returns:
        True if download succeeded, False otherwise
        
    Raises:
        None - errors are caught and logged
    """
    try:
        response = requests.get(url, timeout=300)
        if response.status_code == 200:
            with open(destination, 'wb') as f:
                f.write(response.content)
            return True
        else:
            print(f"Download failed: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"Download error: {e}")
        return False
```

### 4. Test Thoroughly

#### OneDrive Backup Testing
- [ ] Basic functionality (authentication, file download)
- [ ] Edge cases (large files >1GB, special characters in names)
- [ ] Resume capability (Ctrl+C then restart)
- [ ] Error handling (network failures, invalid paths)
- [ ] Both local and online login methods

#### OneNote Exporter Testing
- [ ] Basic functionality (authentication, page export)
- [ ] Attachment downloads (images, audio, PDFs)
- [ ] Multiple export formats (Markdown, ENEX, HTML)
- [ ] Import to target apps (test at least one app)
- [ ] Edge cases (empty notebooks, large attachments)
- [ ] Error handling (token expiration, network issues)

### 5. Update Documentation

**If you're adding features:**
- Update relevant README.md file(s)
- Add examples if applicable
- Update docstrings for modified functions
- Add to CHANGELOG.md (if exists)

**If you're fixing bugs:**
- Add note to TROUBLESHOOTING section
- Update any affected documentation

### 6. Commit Your Changes

```bash
git add .
git commit -m "Add feature: brief description"
```

**Commit message guidelines:**
- Use present tense ("Add feature" not "Added feature")
- Be descriptive but concise
- Reference issues if applicable ("Fixes #123")
- Prefix with tool name for clarity:
  - `[OneDrive] Add incremental backup support`
  - `[OneNote] Fix audio file download issue`
  - `[Shared] Improve error handling`

### 7. Push and Submit PR

```bash
git push origin your-branch-name
```

Then open a Pull Request on GitHub with:
- **Clear title** - What does it do?
- **Description** - Why is this change needed?
- **Testing** - How did you test it?
- **Related issues** - Link any relevant issues
- **Screenshots** - If UI changes (future GUIs)

### 8. Wait for Review

- Respond to feedback promptly
- Make requested changes
- Be patient - reviews may take a few days
- Keep discussions professional and constructive

## 🎯 Areas We'd Love Help With

### High Priority (Both Tools)

- [ ] **Work/school account support** - Different OAuth flows
- [ ] **Better error messages** - More helpful to users
- [ ] **Progress indicators** - Show file size, ETA
- [ ] **Configuration files** - Save credentials securely
- [ ] **Resume capability** - Better handling of interruptions
- [ ] **Unit tests** - Automated testing

### OneDrive Backup Specific

- [ ] **Incremental backup** - Only download changed files
- [ ] **Compression options** - Compress backups
- [ ] **Scheduled backups** - Cron/Task Scheduler integration
- [ ] **Selective sync** - Choose specific folders
- [ ] **Multi-account support** - Backup multiple accounts
- [ ] **GUI version** - For non-technical users

### OneNote Exporter Specific

- [ ] **Better Markdown conversion** - Use html2text library
- [ ] **Direct app imports** - Use Joplin/Evernote APIs
- [ ] **Selective export** - Choose specific notebooks
- [ ] **OCR for handwriting** - Make handwritten notes searchable
- [ ] **Better formatting preservation** - Tables, complex layouts
- [ ] **GUI version** - For easier use

### Shared Improvements

- [ ] **Common authentication module** - Reduce code duplication
- [ ] **Unified CLI** - Single tool with subcommands
- [ ] **Docker containers** - Easy deployment
- [ ] **Web interface** - Browser-based management
- [ ] **Logging system** - Better debugging
- [ ] **Multi-language support** - i18n

## 📚 Code Structure

### OneDrive Backup

```python
class OneDriveBackup:
    def __init__(self): ...
    def authenticate(self): ...
    def download_files(self): ...
    def backup_files(self): ...
```

**Key methods to understand:**
- `authenticate()` - Handles OAuth flow
- `download_from_api()` - Downloads via Graph API
- `backup_files()` - Copies from local OneDrive

### OneNote Exporter

```python
class OneNoteExporter:
    def __init__(self): ...
    def authenticate(self): ...
    def get_notebooks(self): ...
    def export_notebook(self): ...
    def extract_attachments(self): ...
```

**Key methods to understand:**
- `authenticate()` - Handles OAuth flow
- `get_page_content()` - Retrieves page HTML
- `extract_attachments()` - Downloads media files
- `export_for_joplin()` - Converts to Markdown
- `export_for_evernote()` - Converts to ENEX

## 🔐 Security Considerations

When contributing, please:

### Authentication
- Never commit credentials or secrets
- Don't log sensitive user information
- Use secure methods for token storage
- Follow OAuth 2.0 best practices

### Data Handling
- Validate all user inputs
- Sanitize filenames properly
- Handle file permissions correctly
- Don't unnecessarily read file contents

### API Usage
- Respect rate limits
- Handle token refresh properly
- Use appropriate timeouts
- Don't expose API keys

### Example - Secure Token Storage
```python
# ❌ BAD - Logs token
print(f"Token: {access_token}")

# ✅ GOOD - Doesn't expose token
print("✅ Successfully authenticated")
```

## 🧪 Testing Guidelines

### Manual Testing Checklist

**Before submitting PR:**

OneDrive Backup:
- [ ] Test with files of various sizes (small, medium, large)
- [ ] Test with special characters in filenames
- [ ] Test interruption and resume
- [ ] Verify folder structure preserved
- [ ] Check that online-only files are handled correctly

OneNote Exporter:
- [ ] Test with notebooks containing various content types
- [ ] Verify all attachments download
- [ ] Test import to at least one target app
- [ ] Check metadata preservation
- [ ] Verify folder structure matches OneNote

### Automated Testing (Future)

We're working on adding automated tests. Help wanted!

```python
# Example test structure
def test_authentication():
    """Test that authentication flow works"""
    pass

def test_file_download():
    """Test that files download correctly"""
    pass
```

## 📖 Documentation Standards

### README Updates

When adding features, update:
1. Feature list
2. Usage examples
3. Troubleshooting section (if applicable)
4. Roadmap (remove completed items)

### Code Comments

```python
# ❌ BAD - States the obvious
# Loop through files
for file in files:

# ✅ GOOD - Explains why
# Skip hidden files to avoid system conflicts
for file in files:
    if not file.startswith('.'):
```

### Docstrings

```python
def complex_function(param1: str, param2: int) -> Dict:
    """
    One-line summary of what the function does.
    
    More detailed explanation if needed. Can be multiple
    paragraphs describing the logic and any important notes.
    
    Args:
        param1: Description of first parameter
        param2: Description of second parameter
        
    Returns:
        Description of return value
        
    Raises:
        SpecificError: When and why this error occurs
        
    Example:
        >>> result = complex_function("test", 42)
        >>> print(result)
        {'key': 'value'}
    """
```

## 🎨 Code Style

### Formatting
- 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Blank line between functions/methods
- Blank line between logical sections

### Naming Conventions
- `snake_case` for functions and variables
- `PascalCase` for classes
- `UPPER_CASE` for constants
- Descriptive names (avoid single letters except loops)

### Imports
```python
# Standard library
import os
import json
from pathlib import Path

# Third-party
import requests

# Local
from .auth import authenticate
```

## 🤔 Questions?

Feel free to:
- Open an issue with label `question`
- Start a discussion on GitHub
- Reach out to maintainers

## 🏆 Recognition

Contributors will be recognized in:
- README.md credits section
- Release notes for their contributions
- Project documentation

Significant contributions may be highlighted in:
- Blog posts or announcements
- Conference talks or presentations

## 📜 Code of Conduct

### Our Standards

**Be:**
- Respectful and inclusive
- Welcoming to newcomers
- Focused on what's best for the community
- Empathetic towards others
- Open to constructive criticism

**Don't:**
- Harass, troll, or discriminate
- Publish others' private information
- Spam or self-promote unrelated content
- Behave inappropriately in professional context

### Enforcement

Violations will result in:
1. Warning
2. Temporary ban
3. Permanent ban

Report issues to maintainers privately.

## ✅ PR Checklist

Before submitting, ensure:

- [ ] Code follows style guidelines
- [ ] All tests pass (manual testing for now)
- [ ] Documentation updated
- [ ] Commit messages are clear
- [ ] No credentials committed
- [ ] Changes tested with real account
- [ ] Edge cases considered
- [ ] Error handling added

## 🎉 Thank You!

Every contribution helps make these tools better for everyone. Whether it's:
- 🐛 Bug reports
- 💡 Feature suggestions
- 📖 Documentation improvements
- 🔧 Code contributions
- ⭐ Starring the repository
- 💬 Helping others in issues

**You're making a difference!** 🙏

## 📞 Contact

- GitHub Issues: For bugs and features
- GitHub Discussions: For questions and ideas
- Pull Requests: For code contributions

---

**Happy Contributing!** 🚀

*"The best way to predict the future is to implement it."*
