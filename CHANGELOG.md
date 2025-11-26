# Changelog

## [1.3.0](https://github.com/Aleph-Alpha/support/compare/v1.2.3...v1.3.0) (2025-11-26)


### Features

* add flag to control execution of secret generation job and allo… ([#56](https://github.com/Aleph-Alpha/support/issues/56)) ([79ba441](https://github.com/Aleph-Alpha/support/commit/79ba441a758d762c1c264c35beaa0275aa5a74d7))
* add helm config options for pg cluster backup to s3 object storage ([#59](https://github.com/Aleph-Alpha/support/issues/59)) ([c37d327](https://github.com/Aleph-Alpha/support/commit/c37d3272edbcc06551e54afb81b7ec44419f2e51))
* Db migration script ([#54](https://github.com/Aleph-Alpha/support/issues/54)) ([4af53ec](https://github.com/Aleph-Alpha/support/commit/4af53ec1464f84bb62aeff99cb83a28f75ff0015))


### Bug Fixes

* improve scanners to support cosign v3+ ([b8e4197](https://github.com/Aleph-Alpha/support/commit/b8e419792e4f7aea70a9ba2cd08599eac5ca5058))
* redisConfig ([2ec9371](https://github.com/Aleph-Alpha/support/commit/2ec9371db6b32d71ab1eec59f05f8720d86018e4))

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
