# Changelog

## [3.1.1](https://github.com/woodleighschool/jamf-recovery-lock/compare/v3.1.0...v3.1.1) (2026-10-09)


### Bug Fixes

* **build:** unify Go toolchain and license tool versions ([a18e2ac](https://github.com/woodleighschool/jamf-recovery-lock/commit/a18e2ac0fc9cc91e677f0be0c145bc7f72c87c61))

## [3.1.0](https://github.com/woodleighschool/jamf-recovery-lock/compare/v3.0.0...v3.1.0) (2026-10-03)


### Features

* **go:** update module golang.org/x/net (v0.49.0 → v0.55.0) [security] ([#51](https://github.com/woodleighschool/jamf-recovery-lock/issues/51)) ([a3bac1b](https://github.com/woodleighschool/jamf-recovery-lock/commit/a3bac1b60e6e9f80223eb308785bfaa5f97ff700))


### Bug Fixes

* **go:** update module resty.dev/v3 (v3.0.0-rc.3 → v3.0.0-rc.4) ([#52](https://github.com/woodleighschool/jamf-recovery-lock/issues/52)) ([7f6ef1b](https://github.com/woodleighschool/jamf-recovery-lock/commit/7f6ef1b018d6a2050cd402c173aaa32649cfab00))
* reconcile recovery candidates from Jamf command history ([3ef1c03](https://github.com/woodleighschool/jamf-recovery-lock/commit/3ef1c03982d70ddc95db5b3b36d6624289d38cd8))
* retain the 1Password SDK client during item operations ([d71d19c](https://github.com/woodleighschool/jamf-recovery-lock/commit/d71d19c9bb719a45850fe1b088af38d69b943fee))

## [3.0.0](https://github.com/woodleighschool/jamf-recovery-lock/compare/v2.0.4...v3.0.0) (2026-10-01)


### ⚠ BREAKING CHANGES

* track confirmed recovery lock rotations

### Features

* **container:** update image golang (1.25 → 1.26) ([#32](https://github.com/woodleighschool/jamf-recovery-lock/issues/32)) ([a9781e5](https://github.com/woodleighschool/jamf-recovery-lock/commit/a9781e56d5387674e9edef14974e312f4cd39958))
* **container:** update image golang (1.26 → 1.27) ([#42](https://github.com/woodleighschool/jamf-recovery-lock/issues/42)) ([9fb7802](https://github.com/woodleighschool/jamf-recovery-lock/commit/9fb78024cca813908e3225a84461fc3239fc2dce))
* **deps:** update module github.com/1password/onepassword-sdk-go (v0.3.1 → v0.4.0) ([#26](https://github.com/woodleighschool/jamf-recovery-lock/issues/26)) ([73e4e7a](https://github.com/woodleighschool/jamf-recovery-lock/commit/73e4e7ab32d1db7b2fad27d013f3e9ab2979c259))
* **deps:** update module github.com/jackc/pgx/v5 (v5.7.6 → v5.10.0) ([#27](https://github.com/woodleighschool/jamf-recovery-lock/issues/27)) ([70f2985](https://github.com/woodleighschool/jamf-recovery-lock/commit/70f29857a5a044dbeabbacc8b0743d4917746ea7))
* **go:** update module github.com/aws/aws-sdk-go-v2/service/s3 (v1.90.0 → v1.97.3) [security] ([#38](https://github.com/woodleighschool/jamf-recovery-lock/issues/38)) ([d2a5de3](https://github.com/woodleighschool/jamf-recovery-lock/commit/d2a5de313abd699b34a1c654a856b4f004e50a9d))
* **go:** update module github.com/jackc/pgx/v5 (v5.10.0 → v5.11.0) ([#46](https://github.com/woodleighschool/jamf-recovery-lock/issues/46)) ([1f12d2a](https://github.com/woodleighschool/jamf-recovery-lock/commit/1f12d2ac56e634715dbc568753be8f0ca934ef1c))
* **go:** update module golang.org/x/crypto (v0.51.0 → v0.52.0) [security] ([#49](https://github.com/woodleighschool/jamf-recovery-lock/issues/49)) ([525aeca](https://github.com/woodleighschool/jamf-recovery-lock/commit/525aeca10bc9c05481283c16d3c2ebda8dd7384b))
* **go:** update module golang.org/x/net (v0.46.0 → v0.55.0) [security] ([#45](https://github.com/woodleighschool/jamf-recovery-lock/issues/45)) ([d71162e](https://github.com/woodleighschool/jamf-recovery-lock/commit/d71162e11dfb109e292de50c3aaadda185efbf15))
* track confirmed recovery lock rotations ([83896df](https://github.com/woodleighschool/jamf-recovery-lock/commit/83896dfdae93c631ed6587c7ac359e1ce03d64c4))


### Bug Fixes

* **deps:** update module github.com/spf13/cobra (v1.10.1 → v1.10.2) ([#25](https://github.com/woodleighschool/jamf-recovery-lock/issues/25)) ([dca59f0](https://github.com/woodleighschool/jamf-recovery-lock/commit/dca59f0105dd57a1f690a8fb470d7966f4ab197f))
* **go:** update module github.com/1password/onepassword-sdk-go (v0.4.0 → v0.4.1) ([#35](https://github.com/woodleighschool/jamf-recovery-lock/issues/35)) ([0c555fe](https://github.com/woodleighschool/jamf-recovery-lock/commit/0c555fedc36797a3088d1980c68d221f65e6f767))
* **go:** update module github.com/antchfx/xpath (v1.3.5 → v1.3.6) [security] ([#41](https://github.com/woodleighschool/jamf-recovery-lock/issues/41)) ([7617614](https://github.com/woodleighschool/jamf-recovery-lock/commit/7617614e5f8ffd02f40e51fc63f31de4b7ae5aeb))
* **go:** update module github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream (v1.7.3 → v1.7.8) [security] ([#37](https://github.com/woodleighschool/jamf-recovery-lock/issues/37)) ([3293493](https://github.com/woodleighschool/jamf-recovery-lock/commit/3293493084e68aa47ce7eb3272c03c60c4799b91))
* seed releases from published versions ([b6d4c38](https://github.com/woodleighschool/jamf-recovery-lock/commit/b6d4c382437ffcb7d86067c92e4832f73cb61154))


### Build System

* adopt shared Go tooling and container releases ([07a0f08](https://github.com/woodleighschool/jamf-recovery-lock/commit/07a0f0879c40f4c3f819d151e286105f44963063))


### Continuous Integration

* **github-action:** Update action actions/checkout (v5.0.0 → v5.0.1) ([3ce7404](https://github.com/woodleighschool/jamf-recovery-lock/commit/3ce74041e3f0fb04052832a2c53d877e9179ac0f))
* **github-action:** Update action actions/checkout (v5.0.1 → v7.0.0) ([#33](https://github.com/woodleighschool/jamf-recovery-lock/issues/33)) ([e686cfc](https://github.com/woodleighschool/jamf-recovery-lock/commit/e686cfc75d4bdb9630d8a247eaae6ab1d8473bb9))
* **github-action:** Update action actions/checkout (v7.0.0 → v7.0.1) ([b166528](https://github.com/woodleighschool/jamf-recovery-lock/commit/b166528301f8a43a1d47c88e7d028cf7d8b7ede5))
* **github-action:** Update action docker/build-push-action (v6.18.0 → v6.19.2) ([4d98a7c](https://github.com/woodleighschool/jamf-recovery-lock/commit/4d98a7c9a956dde0ac6f830958b494d0b487deba))
* **github-action:** Update action docker/build-push-action (v6.19.2 → v7.3.0) ([#34](https://github.com/woodleighschool/jamf-recovery-lock/issues/34)) ([52c3183](https://github.com/woodleighschool/jamf-recovery-lock/commit/52c31836a15b4b6cf9d40a7085ba1f90f7e5ced4))
* **github-action:** Update action docker/login-action (v3.6.0 → v4.4.0) ([#28](https://github.com/woodleighschool/jamf-recovery-lock/issues/28)) ([a1b8ab8](https://github.com/woodleighschool/jamf-recovery-lock/commit/a1b8ab8592a972d32bd8d2a9e1a4383a24923fe4))
* **github-action:** Update action docker/login-action (v4.4.0 → v4.5.0) ([38f9d23](https://github.com/woodleighschool/jamf-recovery-lock/commit/38f9d23a172ffbb93d95a0bf27cc82f58bb98b58))
* **github-action:** Update action docker/login-action (v4.5.0 → v4.5.1) ([8e3f5dd](https://github.com/woodleighschool/jamf-recovery-lock/commit/8e3f5dd222d24c9bbbd7adcddcb3be9205887baf))
* **github-action:** Update action docker/login-action (v4.5.1 → v4.5.2) ([d66941e](https://github.com/woodleighschool/jamf-recovery-lock/commit/d66941e91c8da69ca45eff1f4c47cc8d597eef7b))
* **github-action:** Update action docker/login-action (v4.5.2 → v4.6.0) ([8e72f2f](https://github.com/woodleighschool/jamf-recovery-lock/commit/8e72f2f0f561b4e37c5b72ee4a2baf090a74b0af))
* **github-action:** Update action docker/metadata-action (v5.9.0 → v6.2.0) ([#29](https://github.com/woodleighschool/jamf-recovery-lock/issues/29)) ([fc25157](https://github.com/woodleighschool/jamf-recovery-lock/commit/fc25157b8d35422b316b92706e1ca166f595c6ba))
* **github-action:** Update action docker/setup-buildx-action (v3.11.1 → v4.2.0) ([#30](https://github.com/woodleighschool/jamf-recovery-lock/issues/30)) ([331e3e2](https://github.com/woodleighschool/jamf-recovery-lock/commit/331e3e285d1c0ae326baf9b062e507d64ecab3ce))
* **github-action:** update action docker/setup-buildx-action (v4.2.0 → v4.3.0) ([#43](https://github.com/woodleighschool/jamf-recovery-lock/issues/43)) ([30274c8](https://github.com/woodleighschool/jamf-recovery-lock/commit/30274c8e8790a1f1f365f0b80b69e638c4ba30a6))
* **renovate:** use shared configuration ([ba8e0e9](https://github.com/woodleighschool/jamf-recovery-lock/commit/ba8e0e950a25b48c4422866a2cfc53536dc3b1e3))
* use the dispatch app for renovate runs ([67bb59f](https://github.com/woodleighschool/jamf-recovery-lock/commit/67bb59f0caff287a38031e75884d0fa4b3af32f8))


### Miscellaneous Chores

* Adding codeowners ([4a0d7a6](https://github.com/woodleighschool/jamf-recovery-lock/commit/4a0d7a6c732ad204a9cc70f598ba1acc9cbff80c))
* **deps:** update docker/metadata-action action to v5.9.0 ([c123bdb](https://github.com/woodleighschool/jamf-recovery-lock/commit/c123bdbba5deb7c1d52886db6686c09625333f38))
* **deps:** update docker/metadata-action action to v5.9.0 ([d12de6f](https://github.com/woodleighschool/jamf-recovery-lock/commit/d12de6fcb828c9e947b931f17814d1eca1baae10))
* **deps:** update go indirect dependencies ([337722f](https://github.com/woodleighschool/jamf-recovery-lock/commit/337722f7bb7dab689c5d0f59b756b3fd806fc658))
* **deps:** update go indirect dependencies ([208dba6](https://github.com/woodleighschool/jamf-recovery-lock/commit/208dba6d5ccd31c28fb0530fc03f9ca57ccc1ce3))
* **deps:** update go indirect dependencies ([c1a47e7](https://github.com/woodleighschool/jamf-recovery-lock/commit/c1a47e78b055a30433425ec11c6b36472986decd))
* **deps:** update go indirect dependencies ([7f63081](https://github.com/woodleighschool/jamf-recovery-lock/commit/7f630810849ff93d17e6142adaababccb6336b79))
* **github-action:** update action ubuntu (24.04 → 26.04) ([#47](https://github.com/woodleighschool/jamf-recovery-lock/issues/47)) ([6623df9](https://github.com/woodleighschool/jamf-recovery-lock/commit/6623df93ec477c8d8403de73f1a24fd37f000999))
* **github-action:** update github-actions ([#48](https://github.com/woodleighschool/jamf-recovery-lock/issues/48)) ([671045e](https://github.com/woodleighschool/jamf-recovery-lock/commit/671045ead37accdb1efc407bf2cd9403442fd4ed))

## 2.0.4

Existing release lineage. Earlier changes are recorded in Git history and releases.
