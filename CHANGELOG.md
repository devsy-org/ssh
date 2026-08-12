# Changelog

## [1.2.3](https://github.com/devsy-org/ssh/compare/v1.2.2...v1.2.3) (2026-08-12)


### Bug Fixes

* **deps:** update module golang.org/x/crypto to v0.55.0 ([#16](https://github.com/devsy-org/ssh/issues/16)) ([8f77af3](https://github.com/devsy-org/ssh/commit/8f77af36944e791b0ca12053d9f236f18c1d4b09))

## [1.2.2](https://github.com/devsy-org/ssh/compare/v1.2.1...v1.2.2) (2026-07-08)


### Bug Fixes

* **deps:** update module golang.org/x/crypto to v0.54.0 ([#12](https://github.com/devsy-org/ssh/issues/12)) ([044da2a](https://github.com/devsy-org/ssh/commit/044da2ab53e439253922743b2e45b00accee80ab))

## [1.2.1](https://github.com/devsy-org/ssh/compare/v1.2.0...v1.2.1) (2026-07-03)


### Bug Fixes

* **deps:** update module golang.org/x/crypto to v0.53.0 ([#10](https://github.com/devsy-org/ssh/issues/10)) ([6c9217f](https://github.com/devsy-org/ssh/commit/6c9217f1dac9e0a42bb468d4491d3231b881bc20))

## [1.2.0](https://github.com/devsy-org/ssh/compare/v1.1.0...v1.2.0) (2026-05-25)


### Features

* add connection-level keepalive and ConnectionClosingCallback ([#4](https://github.com/devsy-org/ssh/issues/4)) ([7fa2baf](https://github.com/devsy-org/ssh/commit/7fa2baf212ae30a7255eb69f34025c3f67040e11))

## [1.1.0](https://github.com/devsy-org/ssh/compare/v1.0.0...v1.1.0) (2026-04-18)


### Features

* add Unix forwarding server implementations ([836adc0](https://github.com/devsy-org/ssh/commit/836adc0844c7647e11e5471d7056a26b65bb9dc9))
* add x11 support ([#1](https://github.com/devsy-org/ssh/issues/1)) ([b9d7640](https://github.com/devsy-org/ssh/commit/b9d76408223ebffe266635dd9f8753e4232e2fb6))
* configurable server handlers ([8b3cdd4](https://github.com/devsy-org/ssh/commit/8b3cdd49b6d2f0c7aa025abc8453ea231848332c))
* Make the HandleConn method public. ([#120](https://github.com/devsy-org/ssh/issues/120)) ([f6d256e](https://github.com/devsy-org/ssh/commit/f6d256ee25108b6d3495790d649ee19970da10cf))
* port coder/ssh changes to fork ([#5](https://github.com/devsy-org/ssh/issues/5)) ([57f1f7f](https://github.com/devsy-org/ssh/commit/57f1f7fe156bb39b285b53a60cc6070943ed2a8d))
* return ssh.Context ([777ab34](https://github.com/devsy-org/ssh/commit/777ab346580bfadbd48a488111be4569f91aff46))
* return ssh.Context ([dd71f10](https://github.com/devsy-org/ssh/commit/dd71f10d4d7bd8fbc2dac2ea8c28ae267f26dbbd))
* upgrade go to 1.25 ([#2](https://github.com/devsy-org/ssh/issues/2)) ([a452700](https://github.com/devsy-org/ssh/commit/a45270088120f2a1b79d188b2d1bb14e91ef125c))


### Bug Fixes

* add checkout step to release workflow for auto-merge ([#25](https://github.com/devsy-org/ssh/issues/25)) ([04f1a19](https://github.com/devsy-org/ssh/commit/04f1a19a7b78ddf860a52730e254b30d0f61c787))
* address lint issues in golangci config and streamlocal ([#9](https://github.com/devsy-org/ssh/issues/9)) ([e15de8f](https://github.com/devsy-org/ssh/commit/e15de8f6fc950cce962dfa4691b8de5158641ad7))
* KeyboardInteractive Login ([1593226](https://github.com/devsy-org/ssh/commit/1593226ea992f6f5f14de8113cfa8ca511dcfd47))
* remove revive rule overrides and fix all resulting violations ([#21](https://github.com/devsy-org/ssh/issues/21)) ([757e9f2](https://github.com/devsy-org/ssh/commit/757e9f2aa2be13b0db5a5345043e52363e2eb305))
* resolve all remaining lint issues ([#20](https://github.com/devsy-org/ssh/issues/20)) ([9251de4](https://github.com/devsy-org/ssh/commit/9251de43075d7153916ab1e7d7ff84a180ec4f77))
* resolve errcheck lint issue in streamlocal.go ([#14](https://github.com/devsy-org/ssh/issues/14)) ([1f166c4](https://github.com/devsy-org/ssh/commit/1f166c48d6f01528685058dfce0fc724e7e0423b))
* resolve errcheck lint issues in conn.go ([#11](https://github.com/devsy-org/ssh/issues/11)) ([51e7394](https://github.com/devsy-org/ssh/commit/51e739410f7da352304186622b7ace6ea691929d))
* resolve gosec lint issues in x11.go ([#19](https://github.com/devsy-org/ssh/issues/19)) ([edebb51](https://github.com/devsy-org/ssh/commit/edebb510092d6dc6e51f07ebdaf50fdcd8c066c1))
* resolve lint issues in agent.go ([#10](https://github.com/devsy-org/ssh/issues/10)) ([be1e766](https://github.com/devsy-org/ssh/commit/be1e76613a03c2809c5149f5e972e99fa4cbcef1))
* resolve lint issues in options.go ([#12](https://github.com/devsy-org/ssh/issues/12)) ([916b0bf](https://github.com/devsy-org/ssh/commit/916b0bf99d77065d1cf3e630104d9d641537be34))
* resolve lint issues in server.go ([#16](https://github.com/devsy-org/ssh/issues/16)) ([7b416ea](https://github.com/devsy-org/ssh/commit/7b416ea1f2b7a2bb9355590dcd2378bab1106d82))
* resolve lint issues in session_test.go and server_test.go ([#18](https://github.com/devsy-org/ssh/issues/18)) ([8f6a171](https://github.com/devsy-org/ssh/commit/8f6a1718e1cafcfc76031cd8ad3ae4e85c086a33))
* resolve lint issues in session.go ([#17](https://github.com/devsy-org/ssh/issues/17)) ([5139e64](https://github.com/devsy-org/ssh/commit/5139e64d81e8937a3e550c2b5da13a518e621279))
* resolve lint issues in tcpip.go ([#15](https://github.com/devsy-org/ssh/issues/15)) ([f831916](https://github.com/devsy-org/ssh/commit/f831916d29ce1a0f50cc67e0b91d495512b84156))
* resolve lint issues in test files ([#13](https://github.com/devsy-org/ssh/issues/13)) ([374100f](https://github.com/devsy-org/ssh/commit/374100fc619a681b161dc6c4f4a29a908868f531))
* use filepath instead of path for cross-plaform compatibility ([1471138](https://github.com/devsy-org/ssh/commit/14711385e6a2bdca49a2446e4d134a8b4e46011b))
* use idiomatic go ([570aa23](https://github.com/devsy-org/ssh/commit/570aa23f40f362f3cb19c14cfbaf0e60112feea0))

## Changelog
