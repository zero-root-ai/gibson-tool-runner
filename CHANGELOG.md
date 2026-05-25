# Changelog

## [0.106.1](https://github.com/zero-day-ai/gibson-tool-runner/compare/v0.106.0...v0.106.1) (2026-05-24)


### Bug Fixes

* **ci:** remove PR trigger and use security-extended for CodeQL ([#53](https://github.com/zero-day-ai/gibson-tool-runner/issues/53)) ([5dc4df4](https://github.com/zero-day-ai/gibson-tool-runner/commit/5dc4df4df4be82d8e4e1948a9d309eb04344e19d)), closes [#52](https://github.com/zero-day-ai/gibson-tool-runner/issues/52)
* **security:** add SysProcAttr/rlimit/output-cap sandbox to child tool invocations ([#55](https://github.com/zero-day-ai/gibson-tool-runner/issues/55)) ([39f55fa](https://github.com/zero-day-ai/gibson-tool-runner/commit/39f55fa75de1b9e905f298e2d0d3cdf189982787))

## [0.106.0](https://github.com/zero-day-ai/gibson-tool-runner/compare/v0.105.0...v0.106.0) (2026-05-24)


### Features

* **runner:** implement dispatch loop — decode → policy → Execute → ABI emit (closes [#33](https://github.com/zero-day-ai/gibson-tool-runner/issues/33)) ([#44](https://github.com/zero-day-ai/gibson-tool-runner/issues/44)) ([3e8a395](https://github.com/zero-day-ai/gibson-tool-runner/commit/3e8a395675222e44853654ef8bd7ebc182f5e21c))

## [0.105.0](https://github.com/zero-day-ai/gibson-tool-runner/compare/v0.104.0...v0.105.0) (2026-05-20)


### Features

* consume platform-clients for transport observability and readiness ([#29](https://github.com/zero-day-ai/gibson-tool-runner/issues/29)) ([d740562](https://github.com/zero-day-ai/gibson-tool-runner/commit/d7405625caa88700212c947021b4735c147bf102))

## 1.0.0 (2026-05-10)


### Features

* add CodeQL and Scorecard workflows ([#1](https://github.com/zero-day-ai/gibson-tool-runner/issues/1)) ([886eb0e](https://github.com/zero-day-ai/gibson-tool-runner/commit/886eb0e25061dab9bc01632a921bc971053cb901))
* install release-please and pr-title-lint ([#2](https://github.com/zero-day-ai/gibson-tool-runner/issues/2)) ([b5883fb](https://github.com/zero-day-ai/gibson-tool-runner/commit/b5883fbd28cd5b8bffc9f36debb2b55f75f9e777))
* per-tool args allowlist for 8 parsers + Go-CVE CI policy ([5d16fc7](https://github.com/zero-day-ai/gibson-tool-runner/commit/5d16fc77281bd44ec07f754c7666775afa3a7f1a))


### Bug Fixes

* **deps:** bump SDK to v1.3.1, grpc to v1.81.0, docker to v28.5.2 ([e47196b](https://github.com/zero-day-ai/gibson-tool-runner/commit/e47196bfa03ed302821a3edb0b9046324660809d))
