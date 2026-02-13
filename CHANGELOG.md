# Changelog

## [1.3.0](https://github.com/Aleph-Alpha/support/compare/v1.2.11...v1.3.0) (2026-02-13)


### Features

* add pharia backup and restore ([#74](https://github.com/Aleph-Alpha/support/issues/74)) ([404994b](https://github.com/Aleph-Alpha/support/commit/404994be12047c52c4d4ceb75631c52337a902fe))
* add scripts for qdrant backup and restore ([#81](https://github.com/Aleph-Alpha/support/issues/81)) ([48ecf4c](https://github.com/Aleph-Alpha/support/commit/48ecf4c72b26dc9c69836902126dc932f114fb8d))
* add support charts for mariadb ([49e4bc9](https://github.com/Aleph-Alpha/support/commit/49e4bc9cf523bd1213e1b7aa56fdce6b467ee6a7))
* add Triage File exist report ([#80](https://github.com/Aleph-Alpha/support/issues/80)) ([86251b8](https://github.com/Aleph-Alpha/support/commit/86251b8d181b6ae3a59cad31f60374f78986bfbe))
* CVE scanner in python ([#75](https://github.com/Aleph-Alpha/support/issues/75)) ([aa5a8b5](https://github.com/Aleph-Alpha/support/commit/aa5a8b57beaa30e83b9a8f5ab2daf41022d5551b))
* increase max user connections for temporal database ([#73](https://github.com/Aleph-Alpha/support/issues/73)) ([d9dee48](https://github.com/Aleph-Alpha/support/commit/d9dee482f42ee010359cb9af39bf8a53379ddeea))
* **oras:** pass mininum level ([#87](https://github.com/Aleph-Alpha/support/issues/87)) ([00005fc](https://github.com/Aleph-Alpha/support/commit/00005fc752e17e6f47e1ca3eb2d2e52b250e2bdf))
* **sbom:** generate sbom report after image scan ([#83](https://github.com/Aleph-Alpha/support/issues/83)) ([9e821e5](https://github.com/Aleph-Alpha/support/commit/9e821e55d3c307a59fd8e4baca4bff08545879c2))
* **triage:** add triage retrieval script for scheduled workflow ([#96](https://github.com/Aleph-Alpha/support/issues/96)) ([e759ee4](https://github.com/Aleph-Alpha/support/commit/e759ee40378ad8d72b8c42c31aa143fac08e7e02))


### Bug Fixes

* **cnpg:** external cluster issue ([#89](https://github.com/Aleph-Alpha/support/issues/89)) ([fbdb9f6](https://github.com/Aleph-Alpha/support/commit/fbdb9f6a8c38522aad85d9ac9d167966da2870d1))
* **deps:** update dependency ([#93](https://github.com/Aleph-Alpha/support/issues/93)) ([7ff7b19](https://github.com/Aleph-Alpha/support/commit/7ff7b199d9d135705da61e75bb77667a00cc6a39))
* **header:** update image field length ([#94](https://github.com/Aleph-Alpha/support/issues/94)) ([3dd4683](https://github.com/Aleph-Alpha/support/commit/3dd4683570582e7ba1d91073d51127e39e0a58e2))
* Resolve pre-commit violation issues ([#85](https://github.com/Aleph-Alpha/support/issues/85)) ([078f7e7](https://github.com/Aleph-Alpha/support/commit/078f7e717bd57c4f1f07f05ebfa4185e9d883f80))

## [1.2.2](https://github.com/Aleph-Alpha/support/compare/v1.2.1...v1.2.2) (2025-10-01)


### Bug Fixes

* improve handling of output for verify-image script ([#10](https://github.com/Aleph-Alpha/support/issues/10)) ([ea3e68e](https://github.com/Aleph-Alpha/support/commit/ea3e68e0d099bf327860f1193965500f54a67ab0))
* make cosign-verify fully silent in case of errors ([#12](https://github.com/Aleph-Alpha/support/issues/12)) ([6f0d5ef](https://github.com/Aleph-Alpha/support/commit/6f0d5efcd8930d0da9366904fd0e26f8797f26fa))

## [1.2.1](https://github.com/Aleph-Alpha/support/compare/v1.2.0...v1.2.1) (2025-09-30)


### Bug Fixes

* fix requirements for k8s-image-scanner ([63dd65d](https://github.com/Aleph-Alpha/support/commit/63dd65d03a46bd86801d46f6ed59fa9678cb2681))

## [1.2.0](https://github.com/Aleph-Alpha/support/compare/v1.1.0...v1.2.0) (2025-09-30)


### Features

* scan script to scan k8s pods for cves from their root signed images ([#6](https://github.com/Aleph-Alpha/support/issues/6)) ([79bae93](https://github.com/Aleph-Alpha/support/commit/79bae938f11f57256ec9cb4fb44a0eb0c8d25e5a))

## [1.1.0](https://github.com/Aleph-Alpha/support/compare/v1.0.0...v1.1.0) (2025-09-27)


### Features

* add --verify option to cosign-extract.sh ([#3](https://github.com/Aleph-Alpha/support/issues/3)) ([a184297](https://github.com/Aleph-Alpha/support/commit/a184297bd0054fd927ecbbe763dbd9d37865a76a))
* image verification script ([#5](https://github.com/Aleph-Alpha/support/issues/5)) ([a015779](https://github.com/Aleph-Alpha/support/commit/a01577999364423cf8206bb7bfc119187931293e))

## 1.0.0 (2025-09-23)


### Features

* extract cosign attestation script ([3e8cab1](https://github.com/Aleph-Alpha/support/commit/3e8cab185a2f106acebd6c30c11337636fce220f))


### Bug Fixes

* **cosign:** support script to extract attestations ([#1](https://github.com/Aleph-Alpha/support/issues/1)) ([488070e](https://github.com/Aleph-Alpha/support/commit/488070e94e2d20bde5df7b7b93cd2afdc253cba1))
* support extra vuln reports ([d3eb64f](https://github.com/Aleph-Alpha/support/commit/d3eb64f460fd587888a271dd24bafe95925302dc))
