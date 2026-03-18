# jwt-term Roadmap

## Phase 2: Distribution & Polish

### 2.1 AUR Package (Arch Linux)
- **Priority:** High
- **Effort:** Small
- Create a `PKGBUILD` that downloads the pre-built Linux binary from GitHub Releases
- Submit to the AUR as `jwt-term`
- Add AUR install instructions to README
- Consider a `-bin` suffix (`jwt-term-bin`) if a source-build variant is also desired

### 2.2 Winget Manifest (Windows)
- **Priority:** Medium
- **Effort:** Small
- Create a manifest pointing to the `jwt-term-x86_64-pc-windows-msvc.zip` release asset
- Submit PR to [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs)
- Add `winget install jwt-term` instructions to README
- Optionally automate manifest updates via [wingetcreate](https://github.com/microsoft/winget-create) in the release workflow

### 2.3 CHANGELOG.md
- **Priority:** Medium
- **Effort:** Small
- Create a `CHANGELOG.md` following [Keep a Changelog](https://keepachangelog.com) format
- Backfill entries for v1.0.0 and v1.0.1 from git history / release notes
- Update with each new release going forward

### 2.4 Debian Package (.deb)
- **Priority:** Low
- **Effort:** Medium
- Add `[package.metadata.deb]` section to `Cargo.toml` with description, section, and assets
- Add `cargo-deb` step to the release workflow (build `.deb` for x86_64 and aarch64 Linux targets)
- Attach `.deb` files to GitHub Releases
- Add install instructions to README (`sudo dpkg -i jwt-term_*.deb`)

## Suggested Order

| Order | Item | Reason |
|-------|------|--------|
| 1 | 2.3 CHANGELOG.md | Low effort, good practice for all subsequent releases |
| 2 | 2.1 AUR Package | Large Rust-savvy audience on Arch |
| 3 | 2.2 Winget Manifest | Covers Windows users who prefer package managers |
| 4 | 2.4 Debian Package | Broader Linux reach, but more CI complexity |
