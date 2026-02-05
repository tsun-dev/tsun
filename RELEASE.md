# Release Process

This document describes how to create a new release of arete.

## Prerequisites

- Commit access to the repository
- GitHub account with push access
- All tests passing on `develop` branch

## Steps

### 1. Update Version

Edit [`Cargo.toml`](Cargo.toml):
```toml
[package]
version = "0.2.0"  # Increment according to semver
```

Run `cargo build` to update `Cargo.lock`.

### 2. Update CHANGELOG

Edit [`CHANGELOG.md`](CHANGELOG.md):

```markdown
## [0.2.0] - 2026-02-04

### Added
- Feature 1
- Feature 2

### Changed
- Change 1

### Fixed
- Bug fix 1
```

Move items from `[Unreleased]` to the new version section.

### 3. Commit Version Bump

```bash
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "Bump version to 0.2.0"
git push origin develop
```

### 4. Merge to Main (if using main branch for releases)

```bash
git checkout main
git merge develop
git push origin main
```

### 5. Create Git Tag

```bash
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

**The GitHub Actions workflow will automatically:**
- Build binaries for all platforms (linux/mac x86_64 + aarch64)
- Create checksums
- Create a GitHub Release with binaries attached
- Generate release notes from commits

### 6. Verify Release

1. Go to https://github.com/cWashington91/arete/releases
2. Verify all binaries are attached (4 `.tar.gz` files + `checksums.txt`)
3. Test download and installation:

```bash
curl -L https://github.com/cWashington91/arete/releases/download/v0.2.0/arete-linux-x86_64.tar.gz | tar xz
./arete --version
```

### 7. Announce (Optional)

- Update project homepage/docs
- Post on social media
- Notify users

## Versioning

arete follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0): Breaking API changes
- **MINOR** (0.2.0): New features, backward compatible
- **PATCH** (0.2.1): Bug fixes, backward compatible

## Rollback

If a release has issues:

```bash
# Delete local tag
git tag -d v0.2.0

# Delete remote tag
git push --delete origin v0.2.0

# Delete GitHub Release via web UI
# Fix issues, then re-tag
```

## Testing Install Script

Before releasing, test the install script:

```bash
# Test locally
bash install.sh

# Test from GitHub (after pushing)
curl -sSL https://raw.githubusercontent.com/cWashington91/arete/main/install.sh | bash
```
