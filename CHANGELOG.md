# Changelog

## [1.3.0](https://github.com/Aleph-Alpha/support/compare/v1.2.2...v1.3.0) (2025-10-31)


### Features

* add --predicate-only functionality to cosign-extract ([#16](https://github.com/Aleph-Alpha/support/issues/16)) ([9ed2950](https://github.com/Aleph-Alpha/support/commit/9ed29504863035fa9f737e26c27adb7359cdf635))
* add cosign-scan-image script ([#17](https://github.com/Aleph-Alpha/support/issues/17)) ([01abd12](https://github.com/Aleph-Alpha/support/commit/01abd127688e9017cc970da39f3705a0b1c6a628))
* add verify base image script for Chainguard compatibility ([cd57824](https://github.com/Aleph-Alpha/support/commit/cd578249709be4d15a2f404bbd35031db5c3165e))
* consolidate values for customer1 into  values.yaml ([#22](https://github.com/Aleph-Alpha/support/issues/22)) ([92e911f](https://github.com/Aleph-Alpha/support/commit/92e911f259e7674c219c8bdd8a11cb27cc561ad1))


### Bug Fixes

* add fullnameoverride ([#28](https://github.com/Aleph-Alpha/support/issues/28)) ([afa7edd](https://github.com/Aleph-Alpha/support/commit/afa7edd48d122404c1fb1daa67b28da2c0071417))
* improve error output with multiline error support ([79f11db](https://github.com/Aleph-Alpha/support/commit/79f11dbe733e2d7d4f64e6f195931785f3101671))
* improve tabular output in cosign-scan utility ([5362a3c](https://github.com/Aleph-Alpha/support/commit/5362a3c1c3595de235c535fc13f9fdc7ae67e72f))
* k8s-image-scanner now scan SBOM and not image directly ([#14](https://github.com/Aleph-Alpha/support/issues/14)) ([60cf51f](https://github.com/Aleph-Alpha/support/commit/60cf51f5e2597aff966712450ab06757fdff98d3))
* pre-commit test ([#27](https://github.com/Aleph-Alpha/support/issues/27)) ([05024bd](https://github.com/Aleph-Alpha/support/commit/05024bd5e49d4e99828693ca037e7ab397ba6eb1))
* reducing resource requirements so we can test the chart ([#25](https://github.com/Aleph-Alpha/support/issues/25)) ([68bf3d9](https://github.com/Aleph-Alpha/support/commit/68bf3d92f86958cfb419b0a8b15f6b6a151dd7dc))

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
