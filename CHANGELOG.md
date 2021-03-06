# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [v0.1.2] - 2022-01-27
### Added
- :white_check_mark: pkce: adds tests.

### Changed
- :recycle: options: orders options alphabetically.

### Fixed
- :bug: options: fixes challenge method being able to be set with invalid values.
- :bug: pkce: stops invalid methods from being able to be set.
- :bug: pkce: stops the code verifier length being overwritten if code verifier is set.
- :bug: pkce: ensures getCodeVerifier checks against nilness and emptiness.

## [v0.1.1] - 2022-01-25
### Added
- :memo: README: adds code verifier verification examples.
- :page_facing_up: LICENSE: adds MIT license. Fixes #4.
- :construction_worker: ci/cd: enables github actions. Fixes #3.
- :memo: README: adds go reference, go report and github action build badges.

### Fixed
- :memo: README: fixes a couple of spelling misteaks.
- :rotating_light: pkce: fixes whitespace issues (wsl).
- :rotating_light: validation: simplifies if-return (revive).
- :rotating_light: errors: reduces line lengths (lll).

## [v0.1.0] - 2022-01-25
### Added
- Generation of code verifier and code challenge.
- Code verifier and code challenge spec-compliant validation.
- Verification for an incoming code verifier.
- URL parameter key constants.

[Unreleased]: https://github.com/matthewhartstonge/pkce/compare/v0.1.2...HEAD
[v0.1.2]: https://github.com/matthewhartstonge/pkce/compare/v0.1.1...v0.1.2
[v0.1.1]: https://github.com/matthewhartstonge/pkce/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/matthewhartstonge/pkce/releases/tag/v0.1.0
