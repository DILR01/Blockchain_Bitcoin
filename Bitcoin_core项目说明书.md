# Bitcoin Core 源码项目说明书
 *项目地址：https://github.com/bitcoin/bitcoin/tree/master*
> 适用仓库：`Bitcoin_core/bitcoin`（Bitcoin Core integration/staging tree）
> 代码版本：`CLIENT_VERSION 32.99.0`（`CLIENT_VERSION_IS_RELEASE=false`，即 master 开发分支快照）
> 许可证：MIT（见 `COPYING`）
> 本文档基于对仓库源码、`CMakeLists.txt` 与目录清单的实际勘察编写。凡属推测的结论均标注"（推断）"。

---

## 0. 如何使用本文档

本文档按"由外到内"的顺序组织，建议按需跳读：

| 你想了解 | 直接看 |
| --- | --- |
| 这个项目是什么、由哪些目录组成 | 第 1、2 章 |
| 怎么编译、编译出哪些程序、开关有哪些 | 第 3 章 |
| 整个代码库分成几层、谁依赖谁 | 第 4 章 |
| `src/` 顶层每个 `.h/.cpp` 是干什么的 | 第 5 章 |
| `src/` 下每个子目录（node、wallet、qt、rpc…）的职责与文件 | 第 6 章 |
| 内置第三方库（secp256k1、leveldb…） | 第 7 章 |
| 测试体系（单元测试、功能测试、fuzz、lint、bench） | 第 8 章 |
| 启动、同步、交易中继、挖矿、RPC 的完整调用链 | 第 9 章 |
| 运行时数据目录里都有什么文件 | 第 10 章 |
| 学习路线与术语表 | 第 11、12 章 |

---

## 1. 项目概览

### 1.1 这是什么

Bitcoin Core 是比特币协议的参考实现，也是目前全网绝大多数节点运行的软件。它做四件事：

1. **连接 P2P 网络**：发现对等节点、握手、交换区块与交易（含 v2 加密传输 BIP324）。
2. **完整验证区块链**：从创世块开始校验每个区块的 PoW、难度、时间戳、Coinbase、脚本与 UTXO 一致性，维护最长链（含 assumeutxo 快照加速）。
3. **维护交易池与中继策略**：验证并暂存未确认交易，按手续费/拓扑/RBF/包中继等策略决定转发与打包。
4. **提供钱包与接口**：内置分层确定性（descriptor）钱包，并提供 JSON-RPC、REST、ZMQ、Qt GUI、多进程 IPC 与可嵌入内核库 `libbitcoinkernel`。

### 1.2 技术栈与关键事实

| 项目 | 取值 | 依据 |
| --- | --- | --- |
| 语言标准 | C++20（`CMAKE_CXX_STANDARD 20`，禁用编译器扩展） | `CMakeLists.txt` |
| 构建系统 | CMake ≥ 3.22，禁止 in-source 构建 | `CMakeLists.txt` |
| 版本号 | 32.99.0（开发版） | `CMakeLists.txt: L41-L46` |
| 依赖管理 | 系统库 / `depends/` 交叉编译依赖 / `vcpkg.json` / Guix 可复现构建 | 第 3 章 |
| 核心密码学库 | libsecp256k1 0.8.1（内置源码） | `src/secp256k1/CMakeLists.txt` |
| 键值存储 | LevelDB（内置，UTXO、区块索引、钱包 SQLite 之外的数据） | `src/leveldb` |
| JSON | univalue（内置） | `src/univalue` |
| 集合调和 | minisketch（Erlay 交易中继，BIP330） | `src/minisketch` |
| GUI | Qt（可选，`BUILD_GUI`，默认 OFF） | `src/qt` |
| 支持的链 | mainnet、testnet3、testnet4、signet、regtest | `src/chainparams.cpp` |

### 1.3 一次构建会得到什么

```
必选/默认：
  bitcoind            全节点守护进程（核心产物）
  bitcoin-cli         RPC 命令行客户端
  bitcoin             统一入口（按子命令转发给上面的程序，2025 新增）
  test_bitcoin        单元测试
可选：
  bitcoin-qt          Qt 图形界面（BUILD_GUI=ON）
  bitcoin-wallet      离线钱包工具（ENABLE_WALLET）
  bitcoin-tx          原始交易编辑工具（BUILD_TX）
  bitcoin-util        实用工具（BUILD_UTIL）
  bitcoin-chainstate  实验性：直接用内核库加载/验证链状态（BUILD_UTIL_CHAINSTATE）
  bitcoin-node        多进程模式下的节点进程（ENABLE_IPC）
  bitcoin-gui         多进程模式下的 GUI 进程（ENABLE_IPC + BUILD_GUI）
  bench_bitcoin       性能基准（BUILD_BENCH）
  fuzz                fuzz 测试二进制（BUILD_FUZZ_BINARY）
  libbitcoinkernel    可嵌入内核库（BUILD_KERNEL_LIB）
```

---

## 2. 顶层目录详解

仓库根目录共有 19 个条目，可分为"源码""构建""测试""文档""辅助"五类。

| 目录/文件 | 类别 | 作用 |
| --- | --- | --- |
| `src/` | 源码 | 全部 C++ 源代码，见第 4-6 章。这是项目的本体 |
| `test/` | 测试 | Python 功能/集成测试（`functional/`，289 个用例）、fuzz 运行脚本、lint 规范检查、sanitizer 抑制表 |
| `doc/` | 文档 | 构建说明、设计文档、策略文档、RPC/ZMQ/PSBT 等专题文档、man 手册、release notes |
| `depends/` | 构建 | 可复现交叉编译的依赖构建系统（`make -C depends`），为 Guix/Gitian 提供确定性依赖 |
| `cmake/` | 构建 | 自定义 CMake 模块（查找依赖、编译器特性检测、安装、测试注册等） |
| `contrib/` | 辅助 | 运维与开发辅助脚本：Guix 可复现构建、init 脚本、线性化工具、种子节点生成、签名验证等 |
| `ci/` | 构建/测试 | CI 容器与脚本，按平台/消毒器/fuzz 等维度组织 |
| `share/` | 资源 | 示例配置、图标、Qt 的 Info.plist 模板、`rpcauth.py`、Windows 安装脚本模板 |
| `.github/` | CI | GitHub Actions 工作流（当前仅 `workflows/ci.yml`）与 issue 模板 |
| `.tx/` | 翻译 | Transifex 翻译配置（`config`），翻译从 Transifex 拉取而非直接改仓库 |
| `.git/` | 版本控制 | Git 元数据（分支、标签、对象库） |
| `CMakeLists.txt` | 构建 | 顶层构建入口：版本、选项、依赖查找、子目录编排 |
| `CMakePresets.json` | 构建 | CMake 预设：`windows`、`windows-static`、`libfuzzer`、`libfuzzer-nosan`、`dev-mode` |
| `CTestConfig.cmake` | 测试 | CTest 配置（测试结果提交相关） |
| `vcpkg.json` | 构建 | vcpkg 清单模式依赖声明（feature：qt/tests/wallet/zeromq） |
| `libbitcoinkernel.pc.in` | 构建 | `libbitcoinkernel` 的 pkg-config 模板，安装后供外部项目链接 |
| `README.md` | 文档 | 项目入口说明、测试与翻译流程指引 |
| `CONTRIBUTING.md` | 文档 | 贡献流程、代码审查文化、提交规范 |
| `SECURITY.md` | 文档 | 安全漏洞披露流程（不公开 issue，走 security@bitcoincore.org） |
| `COPYING` | 法务 | MIT 许可证全文 |
| `INSTALL.md` | 文档 | 指向 `doc/build-*.md` 的构建入口 |
| `.editorconfig` | 规范 | 编辑器缩进/换行统一配置 |
| `.gitattributes` | 规范 | Git 属性（导出、语言统计、二进制标记） |
| `.gitignore` | 规范 | 忽略构建产物 |
| `.python-version` | 规范 | Python 版本提示（供 pyenv 使用） |
| `ruff.toml` | 规范 | Python lint/格式化（ruff）配置 |
| `.style.yapf` | 规范 | Python 代码风格（yapf）配置 |

### 2.1 `contrib/` 逐个子目录

| 子目录 | 作用 |
| --- | --- |
| `asmap/` | ASMAP 工具：把 IP→AS 映射转换为节点可用的二进制 asmap 文件 |
| `completions/` | shell 补全脚本（bash、fish），覆盖 `bitcoin-cli` 等命令 |
| `debian/` | Debian 打包版权信息 |
| `devtools/` | 开发工具：`clang-format-diff.py`、`circular-dependencies.py`、`bitcoin-tidy`（自定义 clang-tidy 检查）、IWYU 配置、覆盖率工具、man 生成、`gen-bitcoin-conf.sh` |
| `guix/` | 官方可复现构建（Guix）：`guix-build`、`guix-attest`、`guix-verify`、工具链与签名脚本 |
| `init/` | 系统服务脚本：systemd、OpenRC、init.d、macOS launchd 配置 |
| `linearize/` | 区块链数据线性化/导出工具（`linearize-data.py`、`linearize-hashes.py`） |
| `macdeploy/` | macOS 打包：`macdeployqtplus`、SDK 生成、分离签名 |
| `message-capture/` | P2P 消息抓包文件解析器 |
| `qos/` | 流量 QoS 脚本（`tc.sh`） |
| `seeds/` | DNS 种子节点数据生成（`makeseeds.py`、`generate-seeds.py`）及各网络节点清单 |
| `shell/` | 通用 shell 函数（git 工具、realpath 兼容） |
| `signet/` | signet 币获取脚本与 signet 区块签名矿工工具 |
| `testgen/` | 测试向量生成（如 `key_io` 测试向量） |
| `tracing/` | USDT/eBPF 追踪脚本（P2P 流量、UTXO 缓存、mempool 监控） |
| `utxo-tools/` | 将 UTXO 集导出为 SQLite 的工具 |
| `verify-binaries/` | 校验官方二进制发布包（签名 + SHA256SUMS） |
| `verify-commits/` | 校验 Git 提交历史（GPG 签名、可信根、合并提交白名单） |
| `windeploy/` | Windows 代码签名证书与分离签名脚本 |
| `zmq/` | ZMQ 订阅示例（`zmq_sub.py`） |
| `filter-lcov.py` / `README.md` | 覆盖率过滤脚本与说明 |

### 2.2 `doc/` 中的关键文档

| 文档 | 价值 |
| --- | --- |
| `doc/files.md` | **运行时数据目录结构**（blocks、chainstate、indexes、wallets 等），第 10 章主要依据 |
| `doc/init.md` | **节点初始化流程**（从 `main()` 到各子系统），第 9 章主要依据 |
| `doc/design/libraries.md` | 库的分层设计意图（哪些代码属于哪一层） |
| `doc/design/multiprocess.md` | 多进程架构（bitcoin-node/bitcoin-gui 通过 Cap'n Proto 通信） |
| `doc/design/assumeutxo.md` | assumeutxo 快照设计 |
| `doc/policy/` | mempool 设计、替换策略、术语、包中继策略 |
| `doc/developer-notes.md` | 编码规范、锁使用、日志、错误处理约定，**读源码前必读** |
| `doc/fuzzing.md` | fuzz 测试编写与运行 |
| `doc/build-unix.md` / `build-osx.md` / `build-windows.md` | 各平台构建说明 |
| `doc/dependencies.md` | 依赖清单与最低版本 |
| `doc/JSON-RPC-interface.md` / `REST-interface.md` / `zmq.md` | 对外接口说明 |
| `doc/psbt.md` / `descriptors.md` / `managing-wallets.md` | 钱包相关专题 |
| `doc/multiprocess.md` / `external-signer.md` / `i2p.md` / `tor.md` / `cjdns.md` | 特性专题 |
| `doc/release-notes/` 与 `release-notes-*.md` | 版本变更记录（当前开发周期的特性说明） |
| `doc/man/` | 由 `--help` 生成的 man 页源文件 |
| `doc/Doxyfile.in`、`README_doxygen.md` | Doxygen API 文档配置 |

---

## 3. 构建系统与产物

### 3.1 静态库划分（核心）

`src/CMakeLists.txt` 把源码组织成一组静态库，依赖方向自下而上，不允许反向依赖：

```
                 bitcoin (wrapper)   bitcoind   bitcoin-cli   bitcoin-tx   bitcoin-util
                        │               │           │             │            │
                        └───────┬───────┴───────────┴─────────────┴────────────┘
                                │
        ┌───────────────────────┼──────────────────────────┐
        │                       │                          │
  bitcoin_qt (可选)      bitcoin_wallet (可选)        bitcoin_node
        │                       │                          │
        └──────────┬────────────┴──────────────┬───────────┘
                   │                           │
             bitcoin_common  ────────────► bitcoin_consensus
                   │                           │
             bitcoin_util  ─────────────► bitcoin_crypto
                   │                           │
                   └──────► core_interface ◄───┘   (仅编译选项，无代码)
```

| 库 | 组成 | 说明 |
| --- | --- | --- |
| `core_interface` | INTERFACE 库 | 只承载统一的编译/链接选项、Boost/Threads 依赖，不含代码 |
| `bitcoin_clientversion` | `clientversion.cpp` | 版本字符串，独立成库以便生成 build info |
| `bitcoin_crypto` | `src/crypto/*` | 纯密码学原语（哈希、AES、ChaCha20、SipHash、MuHash），**不依赖 secp256k1** |
| `bitcoin_util` | `src/util/*` | 通用基础设施（fs、线程、时间、字符串、日志、错误类型、参数解析等），可被任何层复用 |
| `bitcoin_consensus` | `arith_uint256`、`hash`、`uint256`、`pubkey`、`primitives/*`、`script/{interpreter,script,script_error}`、`consensus/{merkle,tx_check}` | 共识关键代码，链接 secp256k1；被 common/node 共用 |
| `bitcoin_common` | 地址编码、链参数、密钥、PSBT、脚本 descriptor/miniscript/sign、policy 基础、网络地址/权限、RPC 请求/工具、调度器、`init/common`、`ipc/listen` | 多个可执行程序共享的"中高层公共能力" |
| `bitcoin_node` | P2P（net/net_processing/addrman/banman）、验证（`validation.cpp`）、mempool、索引、RPC 服务端、HTTP/REST、区块存储、矿工、通知、`init.cpp` | 全节点的全部运行时逻辑 |
| `bitcoin_wallet` | `src/wallet/*` | 可选钱包模块，通过 `walletinitinterface` 挂接到节点 |
| `bitcoin_zmq` | `src/zmq/*` | 可选 ZMQ 通知 |
| `bitcoin_ipc` | `src/ipc/*` + `ipc/capnp/*` | 可选多进程 IPC；关闭时用 `ipc/stub.cpp` 占位 |
| `bitcoin_cli` | `bitcoin-cli.cpp`、`rpc/client.cpp` | RPC 客户端实现（含 HTTP 客户端） |
| `bitcoinqt` | `src/qt/*` | Qt GUI 静态库，链接 node/wallet/common/util/ipc |
| `bitcoinkernel` | `src/kernel/*` + 必要的 node/policy/script/consensus 实现 | 实验性可嵌入内核（C API + C++ 包装） |
| `leveldb` / `univalue` / `minisketch` / `secp256k1` / `crc32c` | 内置第三方 | 见第 7 章 |

### 3.2 主要 CMake 开关

| 选项 | 默认 | 作用 |
| --- | --- | --- |
| `BUILD_BITCOIN_BIN` | ON | 构建统一入口 `bitcoin` |
| `BUILD_DAEMON` | ON | 构建 `bitcoind` |
| `BUILD_CLI` | ON | 构建 `bitcoin-cli` |
| `BUILD_GUI` | OFF | 构建 Qt 界面 `bitcoin-qt` |
| `BUILD_TESTS` | ON | 构建单元测试 |
| `BUILD_TX` / `BUILD_UTIL` | 跟随 `BUILD_TESTS` | 构建 `bitcoin-tx` / `bitcoin-util` |
| `BUILD_GUI_TESTS` | ON（依赖 GUI+TESTS） | 构建 `test_bitcoin-qt` |
| `BUILD_UTIL_CHAINSTATE` | OFF | 构建实验性 `bitcoin-chainstate` |
| `BUILD_KERNEL_LIB` | 跟随上项 | 构建 `libbitcoinkernel` |
| `ENABLE_WALLET` | ON | 启用钱包模块 |
| `BUILD_WALLET_TOOL` | 跟随 `BUILD_TESTS` | 构建 `bitcoin-wallet` |
| `ENABLE_EXTERNAL_SIGNER` | ON | 支持外部签名设备（HWI） |
| `WITH_ZMQ` | OFF | ZMQ 通知 |
| `ENABLE_IPC` | ON（非 Windows） | 构建 `bitcoin-node`/`bitcoin-gui` 多进程程序 |
| `WITH_EXTERNAL_LIBMULTIPROCESS` | OFF | 使用外部 libmultiprocess 而非内置副本 |
| `WITH_EMBEDDED_ASMAP` | ON | 内嵌默认 ASMap 数据 |
| `WITH_USDT` | OFF | USDT 追踪点 |
| `WITH_QRENCODE` / `WITH_DBUS` | 依赖 GUI | 二维码 / DBus 支持 |
| `BUILD_BENCH` | OFF | 构建 `bench_bitcoin` |
| `BUILD_FUZZ_BINARY` | OFF | 构建 `fuzz` |
| `BUILD_FOR_FUZZING` | OFF | 只构建 fuzz（关闭其他所有目标） |
| `REDUCE_EXPORTS` | OFF | 减少导出符号 |
| `CMAKE_COMPILE_WARNING_AS_ERROR` | OFF | 警告即错误 |
| `WITH_CCACHE` | ON | 使用 ccache |

### 3.3 构建方式

```bash
# 方式 A：CMake Preset（推荐，包含依赖查找与常用配置）
cmake --preset dev-mode          # 打开钱包、GUI、ZMQ、IPC、测试等全部特性
cmake --build build --target bitcoind bitcoin-cli
ctest --test-dir build

# 方式 B：传统 CMake
cmake -B build -DBUILD_GUI=ON -DENABLE_WALLET=ON
cmake --build build -j$(nproc)

# 方式 C：可复现构建（推荐用于发布）
make -C depends -j$(nproc)                    # 先构建依赖到 depends/<host>/
cmake -B build --toolchain depends/<host>/toolchain.cmake
# 官方发布使用 contrib/guix/guix-build
```

`vcpkg.json` 提供了 vcpkg 清单模式的等价依赖声明，适合 Windows/MSVC 环境；`depends/` 与 `contrib/guix/` 保证二进制可复现。

---

## 4. 总体架构分层

### 4.1 分层视图

```
┌─────────────────────────────────────────────────────────────────────┐
│ 用户接口层                                                          │
│  bitcoin-cli  │  RPC (rpc/*)  │  REST (rest.cpp)  │  Qt (qt/*)      │
│  ZMQ (zmq/*)  │  IPC (ipc/*)  │  interfaces/* 抽象接口               │
├─────────────────────────────────────────────────────────────────────┤
│ 节点运行时层 (bitcoin_node)                                         │
│  init.cpp（装配） │ net.cpp / net_processing.cpp（P2P）              │
│  validation.cpp（链接/验证） │ txmempool.cpp / txgraph.cpp（交易池）  │
│  node/*（区块存储、链状态、矿工、通知、快照）                        │
├─────────────────────────────────────────────────────────────────────┤
│ 领域模型层 (bitcoin_common + bitcoin_consensus)                     │
│  primitives/*（区块/交易） │ script/*（脚本、descriptor、miniscript）│
│  policy/*（中继策略） │ consensus/*（merkle、tx_verify）             │
│  chainparams / coins / txdb / key / pubkey / psbt                   │
├─────────────────────────────────────────────────────────────────────┤
│ 基础设施层 (bitcoin_util + bitcoin_crypto)                          │
│  serialize/streams │ uint256/hash │ fs/thread/time │ logging        │
│  crypto/*（SHA256、ChaCha20、AES、SipHash） │ util/*（错误、参数…）  │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 依赖规则（理解代码结构的关键）

1. **`util` 与 `crypto` 不知道比特币业务**：不出现 `CBlock`、`CTransaction`，便于测试与复用。
2. **`consensus` 不含网络、磁盘、日志副作用**：只做纯函数式的结构与脚本校验，可被 SPV/内核复用。
3. **`common` 是"多个程序共享的高层代码"**：地址、密钥、PSBT、descriptor、链参数都在这里，因此 `bitcoin-cli`、钱包工具、GUI 都能用。
4. **`node` 持有全局运行时状态**：`NodeContext`（`src/node/context.h`）以依赖注入方式把 mempool、链管理器、网络、通知等传给各子系统，避免全局变量。
5. **`kernel` 是反向约束**：它是"能从节点中剥离出来的最小共识内核"，因此 kernel 只能链接共识相关的底层实现，不能依赖 P2P、RPC、钱包。
6. **钱包与 GUI 是可选插件**：节点通过 `walletinitinterface.h` 与 `interfaces/` 抽象访问钱包/GUI，避免 `bitcoin_node` 直接依赖 `bitcoin_wallet`。

### 4.3 线程模型

| 线程 | 启动位置 | 职责 |
| --- | --- | --- |
| main / init | `bitcoind.cpp` → `init.cpp` | 解析参数、初始化、启动各线程，最后 `WaitForShutdown` |
| scriptcheck（多线程） | `init.cpp` | 并行验证脚本签名（`CCheckQueue`，`checkqueue.h`） |
| net（多线程） | `net.cpp` | 每个对等连接一个线程收发消息（`CConnman::ThreadSocketHandler` 等） |
| msghand | `net_processing.cpp` | 串行处理 P2P 消息（`ThreadMessageHandler`） |
| scheduler | `scheduler.cpp` | 定时任务（flush、mempool 过期、peers 持久化、RPC 超时等） |
| loadblk / import | `init.cpp`、`node/chainstate.cpp` | 启动时加载区块索引、reindex、导入快照 |
| torcontrol / i2p / zmq | 各自模块 | 外部服务交互 |
| HTTP/RPC 工作线程 | `httpserver.cpp` | libevent 线程池处理 RPC/REST 请求 |

---

## 5. `src/` 顶层文件逐个说明

`src/` 顶层直接放置了节点的核心实现（约 155 个代码文件）。下面按功能域分组，**每个文件都列出**。

### 5.1 程序入口与命令行工具

| 文件 | 作用 |
| --- | --- |
| `bitcoind.cpp` | `bitcoind` 的 `main()`：环境初始化、参数解析、调用 `AppInitMain`、进入事件循环与 `Shutdown` |
| `init.cpp` / `init.h` | 全节点初始化装配中心：`AppInitMain` 依次初始化日志、EvalScript 注册、链状态、mempool、索引、网络、RPC、ZMQ、钱包、调度器；`init.h` 定义 `NodeContext`、`BlockAndHeaderTipInfo` 等 |
| `bitcoin.cpp` | 2025 年新增的统一入口 `bitcoin`：按子命令 `gui/node/rpc/wallet/tx/bench/test/...` 转发到对应可执行程序，支持 `--multiprocess` |
| `bitcoin-cli.cpp` | RPC 命令行客户端：HTTP/Unix socket 请求、认证（cookie/rpcauth）、结果格式化、等待 RPC 就绪 |
| `bitcoin-tx.cpp` | 离线创建/修改原始交易（十六进制）的工具 |
| `bitcoin-util.cpp` | 杂项工具入口（当前包含 `grind` 等子命令，用于 PoW 搜索等） |
| `bitcoin-wallet.cpp` | 离线钱包工具入口：创建、信息查询、dump/load、salvage、迁移 |
| `bitcoin-chainstate.cpp` | 实验性程序：直接使用 `libbitcoinkernel` API 加载链状态并验证区块 |
| `noui.cpp` / `noui.h` | 无 GUI 的 `CClientUIInterface` 实现：把界面消息写到 stdout/stderr |
| `walletinitinterface.h` | `WalletInitInterface`：节点只依赖此抽象即可初始化钱包，避免 node→wallet 的编译依赖 |
| `dummywallet.cpp` | `ENABLE_WALLET=OFF` 时的空钱包初始化实现 |
| `external_signer.cpp` / `.h` | 外部签名设备（HWI）支持：发现设备、`enumerate`、发送 PSBT 签名 |
| `*-res.rc` | Windows 资源脚本（图标、版本信息、manifest），非 Windows 构建忽略 |

### 5.2 区块链数据、验证与共识部署

| 文件 | 作用 |
| --- | --- |
| `validation.cpp` | **节点心脏**：`ProcessNewBlock`、`AcceptBlock`、`ActivateBestChain`、`ConnectBlock`/`DisconnectBlock`、`MemPoolAccept`（交易准入）、`LoadChainstate`、`FlushStateToDisk` |
| `validation.h` | `Chainstate`（单条链状态：UTXO 视图、区块索引、高度）、`ChainstateManager`（管理 active/背景链状态，支持 assumeutxo） |
| `validationinterface.h` / `.cpp` | 验证事件订阅框架（`ValidationSignals`）：区块连接/断开、交易加入 mempool 等事件广播给钱包、索引、ZMQ |
| `chain.h` / `chain.cpp` | `CChain`（按高度的索引数组）、`CBlockIndex`（区块元数据）、`CDiskBlockIndex`（磁盘序列化）、分叉查找 |
| `chainparams.cpp` / `.h` | 各网络（main/test/testnet4/signet/regtest）共识参数：创世块、端口、DNS 种子、部署高度、默认策略 |
| `chainparamsbase.cpp` / `.h` | 与网络无关的基础参数（数据目录、RPC 端口等），以及 `-chain` 参数处理 |
| `chainparamsseeds.h` | 由 `contrib/seeds` 生成的内置 DNS 种子哈希 |
| `coins.h` / `coins.cpp` | UTXO 模型：`Coin`、`CCoinsView`（抽象视图）、`CCoinsViewCache`（脏缓存 + 内存 map）、`CCoinsViewBacked` |
| `txdb.h` / `txdb.cpp` | UTXO 持久化：`CCoinsViewDB`（LevelDB 上的 coins 表）、`CBlockTreeDB`（区块索引/flag 表）；含 UTXO 集统计（muhash） |
| `undo.h` | `CTxUndo` / `CBlockUndo`：回滚区块所需的被花费输出数据 |
| `flatfile.h` / `.cpp` | `blk*.dat` / `rev*.dat` 平面文件管理：`FlatFileSeq`、`FlatFilePos`、预分配与定位 |
| `blockencodings.h` / `.cpp` | BIP152 Compact Block：`CompactBlock`、`PartiallyDownloadedBlock`（高带宽中继） |
| `merkleblock.h` / `.cpp` | BIP37 SPV 过滤器：`CPartialMerkleTree`、`CMerkleBlock` |
| `blockfilter.h` / `.cpp` | BIP158 紧凑区块过滤器：`GCSFilter`、`BlockFilter` 构建与匹配 |
| `pow.h` / `.cpp` | 工作量证明：`CheckProofOfWork`、`GetNextWorkRequired`（难度调整） |
| `compressor.h` / `.cpp` | UTXO 磁盘压缩：脚本模板、金额、`CTxOut` 的紧凑编码 |
| `dbwrapper.h` / `.cpp` | LevelDB 封装：`CDBWrapper`、`CDBBatch`、`CDBIterator`、选项与错误类型 |
| `deploymentinfo.h` / `.cpp` | 软分叉部署元信息（名称、BIP9 bit、部署类型 `VBDeploymentInfo`） |
| `deploymentstatus.h` / `.cpp` | 查询部署是否激活（buried 部署按高度，BIP9 按 `VersionBitsCache`） |
| `versionbits.h` / `.cpp` / `versionbits_impl.h` | BIP9 版本位状态机：`ThresholdState`、`AbstractThresholdConditionChecker`、统计与警告 |
| `signet.h` / `.cpp` | signet 的区块签名验证（`SignetTxs`）与挑战脚本解析 |
| `headerssync.h` / `.cpp` | 低带宽区块头预同步（assumeutxo 启动时先同步头部，避免下载无用区块） |
| `txgraph.h/.cpp` + `cluster_linearize.h` | 见 5.3 |

### 5.3 交易池、交易图与交易请求

| 文件 | 作用 |
| --- | --- |
| `txmempool.h` / `.cpp` | 交易池：`CTxMemPool`、`CTxMemPoolEntry`（手续费/祖先/后代统计）、`indexed_transaction_set`、准入与驱逐、`GetTransactionAncestry` |
| `txgraph.h` / `txgraph.cpp` | **cluster mempool 的核心数据结构**：以"簇（cluster）"为单位维护交易依赖 DAG，并维护按费率排序的 chunk 线性化；支持 staging（可回滚的批量修改） |
| `cluster_linearize.h` | 通用线性化算法库：`DepGraph`（祖先/后代集合）、spanning-forest 等算法，供 `TxGraph` 与测试使用 |
| `txrequest.h` / `.cpp` | `TxRequestTracker`：跟踪"应向哪个 peer 请求哪笔交易"，处理超时、重复公告、优先 peer |
| `private_broadcast.h` / `.cpp` | 私有广播：把交易优先直连发送给少量节点（不公开公告），附带重试、过期与确认状态机 |

### 5.4 P2P 网络

| 文件 | 作用 |
| --- | --- |
| `net.h` / `net.cpp` | 连接管理器 `CConnman` 与连接对象 `CNode`：socket 事件循环、连接建立/断开、消息序列化发送、地址广播、限流 |
| `net_processing.h` / `.cpp` | P2P 消息处理核心：`PeerManager`、`Peer` 状态机、`ProcessMessage`（version/verack/ping/inv/getdata/block/tx/headers/feeFilter…）、区块与交易下载调度、DoS 评分 |
| `netaddress.h` / `.cpp` | 网络地址类型：`CNetAddr`、`CSubNet`、`CService`、`CServiceHash`（IPv4/IPv6/Tor/I2P/CJDNS） |
| `netbase.h` / `.cpp` | 网络底层：DNS 解析、代理（SOCKS5）、`ReachableNets`、`LookupHost` |
| `netgroup.h` / `.cpp` | `NetGroupManager`：按 /16（IPv4）等规则计算网络分组，用于地址管理与节点驱逐 |
| `net_permissions.h` / `.cpp` | `NetPermissions`：`noban`、`force relay`、`mempool` 等连接权限解析 |
| `net_types.h` / `.cpp` | 网络相关枚举与类型（连接方向、`CInv` 类型等） |
| `netmessagemaker.h` | `CNetMsgMaker`：用可变参数构造 P2P 消息的模板工具 |
| `protocol.h` / `.cpp` | 协议层常量与结构：`CMessageHeader`（magic/命令/长度/校验和）、`CInv`、`CAddress`、消息命令名 |
| `addrman.h` / `.cpp` / `addrman_impl.h` | 地址管理器：新表/尝试表分桶、`Add`/`Select`/`GetAddr`，抗女巫与地址投毒 |
| `addrdb.h` / `.cpp` | 地址与禁止名单持久化：`peers.dat`、`banlist.json` 的读写 |
| `banman.h` / `.cpp` | `BanMan`：按 IP/子网禁用节点，持久化与自动解禁 |
| `bip324.h` / `.cpp` | BIP324 v2 加密传输：EllSwift ECDH 握手、`BIP324Cipher`（ChaCha20-Poly1305）、消息分片 |
| `i2p.h` / `.cpp` | I2P 支持：通过 SAM 代理建立会话与流 |
| `torcontrol.h` / `.cpp` | Tor 控制端口：`ADD_ONION` 创建隐藏服务、认证 |
| `mapport.h` / `.cpp` | NAT-PMP / UPnP 端口映射（libnatpmp、miniupnpc） |
| `semaphore_grant.h` | `CountingSemaphoreGrant`：限制并发区块请求数等资源配额 |

### 5.5 RPC、HTTP 与 REST

| 文件 | 作用 |
| --- | --- |
| `httprpc.h` / `.cpp` | JSON-RPC over HTTP：请求体解析、`rpcauth`/cookie 认证、批量请求、RPC 命令白名单与超时 |
| `httpserver.h` / `.cpp` | 基于 libevent 的 HTTP 服务器与工作队列，供 RPC 与 REST 共用 |
| `rest.h` / `.cpp` | REST 接口：`/rest/block`、`/rest/tx`、`/rest/chaininfo`、`/rest/getutxos` 等 |
| `rpc/*` | JSON-RPC 命令实现（见 6.11） |

### 5.6 脚本、密钥、地址与钱包数据格式

| 文件 | 作用 |
| --- | --- |
| `script/` | 脚本系统与 descriptor/miniscript（见 6.6） |
| `key.h` / `key.cpp` | `CKey`（私钥）与 secp256k1 上下文封装、ECDSA/Schnorr 签名、密钥派生 |
| `pubkey.h` / `pubkey.cpp` | `CPubKey`（公钥）、`XOnlyPubKey`（Taproot）、`EllSwiftPubKey`（BIP324）、签名校验 |
| `key_io.h` / `.cpp` | 地址编解码：`EncodeDestination` / `DecodeDestination`（base58 与 bech32） |
| `musig.h` / `.cpp` | MuSig2：聚合公钥（`MuSig2AggregatePubkeys`）、BIP328 合成 xpub、秘密 nonce 的安全封装 |
| `addresstype.h` / `.cpp` | `CTxDestination` 变体：`PKHash`、`ScriptHash`、`WitnessV0KeyHash`、`WitnessV0ScriptHash`、`WitnessV1Taproot`、`Anchor`、`PubKeyDestination` |
| `outputtype.h` / `.cpp` | `OutputType`（LEGACY/BECH32/BECH32M）与地址类型转换 |
| `base58.h` / `.cpp` | Base58 与 Base58Check 编码（WIF、legacy 地址、xpub） |
| `bech32.h` / `.cpp` | Bech32 / Bech32m 编解码（BIP173/BIP350） |
| `psbt.h` / `.cpp` | BIP174/371 PSBT：`PartiallySignedTransaction`、输入/输出字段、合并与序列化 |
| `core_io.h` / `.cpp` | 交易/区块的 JSON 表示与十六进制解析（RPC 与 `bitcoin-tx` 使用） |
| `core_memusage.h` | 区块、交易、PSBT 的内存占用估算接口 |

### 5.7 序列化、基础类型与运行时基础设施

| 文件 | 作用 |
| --- | --- |
| `serialize.h` | 序列化框架：POD 序列化、`CompactSize`（varint）、`VARINT`、`Serializer`/`Unserializer`、版本化 `Wrapper` |
| `streams.h` / `.cpp` | 流抽象：`SpanReader`/`SpanWriter`、`VectorReader`/`Writer`、`DataStream`、`AutoFile`、`BufferedFile`、`CAutoFile` |
| `uint256.h` / `.cpp` | `uint160`、`uint256`、`base_blob`：哈希类型、hex 解析、比较 |
| `arith_uint256.h` / `.cpp` | 256 位无符号算术（`base_uint`、`arith_uint256`），用于难度与 PoW 目标计算 |
| `span.h` | `Span` 类型（对 `std::span` 的兼容封装） |
| `prevector.h` | `prevector`：小容量内联存储的序列化向量，减少堆分配 |
| `hash.h` / `hash.cpp` | `Hash()`（双 SHA256）、`CHash256`、`CHash160`、`HashWriter`、SipHash、MurmurHash3、`TaggedHash`（BIP340） |
| `random.h` / `random.cpp` | 随机数：`GetRand`、`FastRandomContext`、`InsecureRandomContext`、`RandomMixin` |
| `randomenv.h` / `.cpp` | 收集系统熵（CPU、内存、时间等）用于初始化 RNG |
| `memusage.h` | `DynamicUsage()`：对 STL 容器递归估算内存 |
| `indirectmap.h` | `indirectmap`：以指针间接比较的 map，用于 coins 缓存等 |
| `cuckoocache.h` | `CuckooCache`：高命中率的缓存淘汰结构（签名缓存、区块过滤器缓存） |
| `sync.h` / `sync.cpp` | 互斥与锁：`Mutex`、`LOCK`、`UniqueLock`、递归锁、锁顺序死锁检测、`WITH_LOCK` |
| `threadsafety.h` | Clang 线程安全分析注解宏（`GUARDED_BY`、`EXCLUSIVE_LOCKS_REQUIRED` 等） |
| `scheduler.h` / `.cpp` | `CScheduler`：基于条件的定时/延迟任务队列（flush、超时、维护任务） |
| `checkqueue.h` | `CCheckQueue`：批量并行校验队列（脚本签名验证） |
| `tinyformat.h` | 类型安全的 `strprintf` 格式化库（第三方，内置） |
| `attributes.h` | 编译器属性宏（`NODISCARD`、`NO_NULL`、`WARN_UNUSED_RESULT` 等） |
| `clientversion.h` / `.cpp` | 版本常量、`FormatFullVersion`、`FormatSubVersion`（P2P user agent） |
| `logging.h` / `logging.cpp` | 日志系统：分类（`LogCategory`）、级别、`LogPrintf`/`LogDebug` 宏、`SourceLocation` |

> 注：`validationinterface.h`、`undo.h`、`merkleblock.h` 已在 5.2 说明，此处不重复。

### 5.8 需要特别注意的"新结构"

1. **`txgraph` + `cluster_linearize`**：这是 cluster mempool 重构的核心。传统 mempool 以单笔交易为一等公民，按祖先/后代统计费率；新结构以"簇"（通过依赖关系连通的交易集合）为粒度，维护 `chunk` 线性化顺序，从而支持更精确的打包与驱逐决策（参考 `doc/policy/mempool-design.md`）。
2. **`private_broadcast`**：面向矿工/关键节点的私有交易广播通道，与公开 `inv` 广播并行，降低被抢先交易的风险。
3. **`bitcoin.cpp`**：2025 年引入的"多合一"命令行封装，是 `bitcoind`/`bitcoin-cli`/`bitcoin-tx` 之上的一层薄壳。
4. **`headerssync`**：为 assumeutxo 服务的"先同步头部、后下载区块"的低带宽模式。
5. **`musig`**：MuSig2 聚合签名（BIP327）与 BIP328 合成 xpub，供 Taproot 多签 descriptor 使用。

---

---

## 6. `src/` 子目录详解

### 6.1 `src/node/` —— 节点运行时状态与子系统

**职责**：存放"节点运行时"的装配与状态代码（`NodeContext`、链状态加载、区块存储、矿工、通知、交易下载），刻意与钱包/GUI 隔离，避免 GUI 改动波及节点。`node/README.md` 明确指出：未来 `validation.cpp`、`txmempool.cpp` 等也会逐步迁入。

| 文件 | 作用 |
| --- | --- |
| `context.h` / `context.cpp` | `NodeContext`：以依赖注入方式持有 chainman、mempool、connman、banman、peerman、通知、调度器等 |
| `abort.h` / `abort.cpp` | `AbortNode`：不可恢复错误时记录并终止进程 |
| `chainstate.h` / `chainstate.cpp` | 链状态加载/校验/重建/快照激活的高层流程（`LoadChainstate`、`VerifyDB`、`ImportBlocks`） |
| `chainstatemanager_args.h` / `.cpp` | `-assumevalid`、`-checkblocks` 等链状态参数 |
| `blockstorage.h` / `blockstorage.cpp` | 区块与 undo 数据的读写（`ReadBlock`、`WriteBlock`、`ReadBlockUndo`）、区块索引数据库、磁盘空间管理 |
| `blockmanager_args.h` / `.cpp` | 区块存储参数（`-blocksdir`、`-prune`、`-fastprune`） |
| `block_template_manager.h` / `.cpp` | 2025 新增：区块模板创建、提交已解区块、等待链尖，为挖矿/RPC 提供统一入口 |
| `block_validation_state_catcher.h` | RAII 工具：捕获并记录区块验证失败状态 |
| `caches.h` / `.cpp` | 按 `-dbcache` 计算 UTXO 缓存、block index 缓存等大小 |
| `coin.h` / `coin.cpp` | UTXO 查询辅助：同时查 mempool 与当前链 UTXO 集（`FindCoins`） |
| `coins_view_args.h` / `.cpp` | UTXO 视图缓存参数 |
| `connection_types.h` / `.cpp` | `ConnectionType`（INBOUND/OUTBOUND/FEELER/BLOCK_RELAY_ONLY 等） |
| `database_args.h` / `.cpp` | 数据库（LevelDB）相关参数（`-dbcrashratio` 等） |
| `eviction.h` / `.cpp` | 对等节点驱逐候选选择与保护逻辑 |
| `indexes.h` / `.cpp` | 初始化/启动各类索引（txindex、blockfilterindex、coinstatsindex） |
| `interfaces.h` / `interfaces.cpp` | `interfaces::Node` 的节点侧实现：GUI/IPC/RPC 通过它访问节点 |
| `interface_ui.h` / `.cpp` | `CClientUIInterface` 与消息队列：把初始化进度、警告推给 GUI |
| `kernel_notifications.h` / `.cpp` | `KernelNotifications`：区块提示变化、警告等内核级通知的汇聚点 |
| `mempool_args.h` / `.cpp` | mempool 参数（`-maxmempool`、`-mempoolexpiry` 等） |
| `mempool_persist.h` / `.cpp` | `mempool.dat` 的写入/读取（`DumpMempool`/`LoadMempool`） |
| `mempool_persist_args.h` / `.cpp` | mempool 持久化参数 |
| `miner.h` / `miner.cpp` | 区块组装：`BlockAssembler`、`CreateNewBlock`（选择交易、计算 coinbase、加入 commitment） |
| `mini_miner.h` / `.cpp` | 轻量矿工：只对单区块做交易选择，供策略测试与模拟 |
| `mining_args.h` / `.cpp` | 挖矿参数（`-blockmintxfee`、`-blockmaxweight`） |
| `mining_types.h` | `BlockCreateOptions`、`BlockWaitOptions`、`CBlockTemplate` 等类型 |
| `minisketchwrapper.h` / `.cpp` | minisketch 全局初始化（Erlay 所需） |
| `peerman_args.h` / `.cpp` | `PeerManager` 参数 |
| `protocol_version.h` | P2P 协议版本常量（`PROTOCOL_VERSION`、最小兼容版本） |
| `psbt.h` / `psbt.cpp` | 节点侧 PSBT 辅助：从链上/mempool 补充 UTXO 信息 |
| `timeoffsets.h` / `.cpp` | 对等节点时间偏移的中位数统计（`-maxtimeadjustment`） |
| `transaction.h` / `.cpp` | 交易提交入口：`BroadcastTransaction`、`SubmitTransaction`、mempool 接收流程封装 |
| `txdownloadman.h` / `txdownloadman_impl.h` / `.cpp` | 交易下载管理器：协调公告（inv）、请求（getdata）、orphan、超时与限流 |
| `txorphanage.h` / `.cpp` | Orphan 交易池：暂存父交易未知的交易，父到齐后重新处理 |
| `txreconciliation.h` / `.cpp` | Erlay（BIP330）：基于 minisketch 的交易集合调和，减少 inv 带宽 |
| `types.h` | 节点层通用类型（如 `BlockSource`） |
| `utxo_snapshot.h` / `.cpp` | assumeutxo 快照的写入、读取与元数据校验 |
| `warnings.h` / `.cpp` | 节点警告集合（`-alertnotify`、大额分叉等） |

### 6.2 `src/kernel/` —— 可嵌入内核库 `libbitcoinkernel`

**职责**：把"验证链状态所必需"的最小代码集合封装成稳定 C API（`bitcoinkernel.h`）与 C++ RAII 包装（`bitcoinkernel_wrapper.h`），供外部项目（如闪电网络、SPV 服务）嵌入。库的源码清单会随着解耦推进逐步收缩。

| 文件 | 作用 |
| --- | --- |
| `bitcoinkernel.h` | 纯 C API：上下文、链参数、区块/交易句柄、验证、通知回调、日志 |
| `bitcoinkernel.cpp` | C API 实现（句柄生命周期、错误转换） |
| `bitcoinkernel_wrapper.h` | C++ 包装：`UniqueHandle`、异常安全接口 |
| `chain.h` / `.cpp` | 内核视角的链管理（与顶层 `chain.h` 不同，专供内核） |
| `chainparams.h` / `.cpp` | 内核可用的链参数（mainnet/testnet/signet/regtest） |
| `checks.h` / `.cpp` | 区块/交易结构检查的内核入口（`CheckBlock`、`CheckTransaction`） |
| `coinstats.h` / `.cpp` | UTXO 集统计（数量、muhash） |
| `context.h` / `.cpp` | `Context`：内核内的链状态 + mempool 容器 |
| `cs_main.h` / `.cpp` | 内核内 `cs_main` 锁定义（避免上层重复定义） |
| `disconnected_transactions.h` / `.cpp` | 区块断开时暂存的交易（用于重放/重组） |
| `mempool_entry.h` / `mempool_limits.h` / `mempool_options.h` / `mempool_removal_reason.h` / `.cpp` | mempool 的公共类型、限制与移除原因（不依赖完整 `CTxMemPool`） |
| `blockmanager_opts.h` / `chainstatemanager_opts.h` | 区块存储与链管理器的选项结构 |
| `caches.h` | 内核侧缓存大小配置 |
| `messagestartchars.h` | 各网络 magic 常量 |
| `notifications_interface.h` | `Notifications` 抽象：区块提示、警告、flush 等回调 |
| `signet.h` | signet 参数的内核视图 |
| `types.h` / `warning.h` | 内核通用类型与警告码 |

### 6.3 `src/consensus/` —— 共识规则（纯逻辑）

| 文件 | 作用 |
| --- | --- |
| `amount.h` | `CAmount`、`COIN`、`MAX_MONEY` 等金额定义 |
| `consensus.h` | 共识常量：出块间隔、减半间隔、`MAX_BLOCK_WEIGHT`、`WITNESS_SCALE_FACTOR` |
| `params.h` | 共识参数上限（脚本大小、签名操作数、锁时间等） |
| `merkle.h` / `merkle.cpp` | Merkle 树与 witness Merkle 树计算/校验、`BlockMerkleRoot`、`ComputeMerkleRoot` |
| `tx_check.h` / `tx_check.cpp` | `CheckTransaction`：交易结构合法性（非空输入输出、金额范围、重复输入、尺寸） |
| `tx_verify.h` / `tx_verify.cpp` | `CheckTxInputs`（金额与成熟度）、`GetBlockSubsidy`、`VerifyCoinbase` |
| `validation.h` | 验证结果类型与模式：`TxValidationResult`、`TxValidationState`、`BlockValidationResult`、`BlockValidationState`、`ValidationMode`（只承载结果，不做规则判定） |

### 6.4 `src/policy/` —— 中继与 mempool 策略（非共识）

| 文件 | 作用 |
| --- | --- |
| `policy.h` / `policy.cpp` | 标准性判定：`IsStandard`、`IsStandardTx`、粉尘阈值、`MAX_STANDARD_TX_WEIGHT`、`GetVirtualTransactionSize` |
| `feerate.h` / `feerate.cpp` | `CFeeRate`：sat/kvB 费率类型与四则运算、舍入规则 |
| `rbf.h` / `rbf.cpp` | BIP125 替换规则：`IsRBFOptIn`、`PreCheckReplacement`、冲突检测 |
| `packages.h` / `packages.cpp` | 交易包（package）拓扑与大小限制，`CheckPackage`、1P1C 包规则 |
| `ephemeral_policy.h` / `.cpp` | 临时粉尘（ephemeral dust）策略：允许零费率父交易携带粉尘，但要求粉尘必须被同包子交易花费，避免污染 UTXO 集 |
| `truc_policy.h` / `.cpp` | v3 / TRUC（Topologically Restricted Until Confirmation，BIP431）交易策略 |
| `settings.h` / `.cpp` | 策略相关运行时设置（`-permitbaremultisig`、`-datacarrier` 等） |
| `fees/block_policy_estimator.h` / `.cpp` | 传统区块内费率估算器（按确认目标统计） |
| `fees/mempool_estimator.h` / `.cpp` | 基于 mempool 的费率估算（更快响应） |
| `fees/estimator_man.h` / `.cpp` | 统一管理两种估算器与 `estimatesmartfee` 数据 |
| `fees/estimator_args.h` / `.cpp` | 估算器参数与持久化 |

> 注：`policy/` 目录下没有 `fees.h`；费率类型 `CFeeRate` 在 `policy/feerate.h`，`FeeEstimateMode`/`FeeReason` 等枚举在 `src/util/fees.h`，估算器实现全部在 `policy/fees/`。

### 6.5 `src/script/` —— 脚本、descriptor 与 Miniscript

| 文件 | 作用 |
| --- | --- |
| `script.h` / `script.cpp` | `CScript`、`CScriptNum`、opcode 定义、脚本拼接与反汇编 |
| `interpreter.h` / `interpreter.cpp` | 脚本解释器：`EvalScript`、`VerifyScript`、签名检查与各 BIP 规则（CLTV/CSV/SegWit/Taproot） |
| `script_error.h` / `.cpp` | `ScriptError` 枚举、错误码与可读信息 |
| `verify_flags.h` | 脚本验证标志（`SCRIPT_VERIFY_P2SH`、`WITNESS`、`TAPROOT` 等） |
| `sign.h` / `sign.cpp` | 交易签名器：`SignatureCreator`、`SignSignature`、sighash 计算 |
| `signingprovider.h` / `.cpp` | `SigningProvider` 抽象（钱包/外部签名器提供密钥与脚本） |
| `descriptor.h` / `descriptor.cpp` | 输出脚本描述符解析与展开（BIP380-386：`pkh()`、`wpkh()`、`tr()`、`multi_a()` 等） |
| `miniscript.h` / `.cpp` | Miniscript：策略语言的解析、类型检查、脚本生成 |
| `parsing.h` / `.cpp` | 脚本与 descriptor 的文本解析工具（`ParseScript`、`Parse`） |
| `keyorigin.h` | BIP32 key origin（`[fingerprint/path]`）表示 |
| `solver.h` / `solver.cpp` | `Solver()`：识别标准脚本模板（P2PKH/P2SH/P2WPKH/P2WSH/P2TR/multisig） |
| `sigcache.h` / `sigcache.cpp` | 签名验证缓存（`CSignatureCache` + cuckoo cache） |

### 6.6 `src/primitives/` —— 区块与交易数据结构

| 文件 | 作用 |
| --- | --- |
| `transaction.h` / `.cpp` | `CTransaction`、`CMutableTransaction`、`CTxIn`、`CTxOut`、`COutPoint`、witness 结构、`GetHash`/`GetWitnessHash` |
| `block.h` / `.cpp` | `CBlockHeader`、`CBlock`、`CBlockLocator`、区块哈希与序列化 |
| `transaction_identifier.h` | `Txid`、`Wtxid` 强类型包装（防止混用） |

### 6.7 `src/index/` —— 可选索引框架

| 文件 | 作用 |
| --- | --- |
| `base.h` / `.cpp` | `BaseIndex`：索引生命周期、与验证信号对接、后台同步线程、`Init`/`Start`/`Stop` |
| `txindex.h` / `.cpp` | 交易索引：`-txindex`，按 txid 查区块位置 |
| `blockfilterindex.h` / `.cpp` | BIP158 区块过滤器索引（供轻客户端查询） |
| `coinstatsindex.h` / `.cpp` | UTXO 集统计索引（`gettxoutsetinfo` 快速返回） |
| `txospenderindex.h` / `.cpp` | 交易输出花费者索引（记录每个 UTXO 被哪笔交易花费） |
| `db_key.h` | 索引数据库 key 编码 |
| `disktxpos.h` | `CDiskTxPos`：交易在 blk 文件中的位置 |
| `txindex_key.h` | txindex 的 key 定义 |

### 6.8 `src/zmq/` —— ZeroMQ 通知

| 文件 | 作用 |
| --- | --- |
| `zmqnotificationinterface.h` / `.cpp` | `CZMQNotificationInterface`：把验证事件转成 ZMQ 消息 |
| `zmqabstractnotifier.h` / `.cpp` | 通知器抽象基类（初始化、通知、错误处理） |
| `zmqpublishnotifier.h` / `.cpp` | 各类发布器：`-zmqpubrawblock`、`-zmqpubrawtx`、`-zmqpubhashblock`、`-zmqpubhashtx`、`-zmqpubsequence` |
| `zmqrpc.h` / `.cpp` | `getzmqnotifications` RPC |
| `zmqutil.h` / `.cpp` | ZMQ 错误码转字符串等工具 |

### 6.9 `src/interfaces/` —— 抽象接口层

**职责**：定义 GUI、IPC、钱包与节点之间的稳定抽象，使 `bitcoin_node` 不反向依赖 `bitcoinqt`/`bitcoin_wallet`。接口只有头文件，实现分散在 `node/interfaces.cpp`、`wallet/interfaces.cpp`、`qt/*`、`ipc/interfaces.cpp`。

| 文件 | 作用 |
| --- | --- |
| `node.h` | `interfaces::Node`：RPC 执行、钱包加载、区块/交易查询、广播交易、退出、初始化状态 |
| `chain.h` | `interfaces::Chain`：`getTip`、`findBlock`、`findTx`、`isInMempool`、`handleNotifications` |
| `wallet.h` | `interfaces::Wallet`：余额、地址、创建交易、PSBT、签名、转储 |
| `mining.h` | `interfaces::Mining`：获取区块模板、提交区块、等待链尖 |
| `echo.h` | `interfaces::Echo`：IPC 连通性测试 |
| `init.h` | `interfaces::Init`：创建上述接口的工厂（各程序提供自己的实现） |
| `ipc.h` | IPC 启动/连接（生成子进程、建立 Cap'n Proto 连接） |
| `rpc.h` | 轻量 RPC 客户端接口 |
| `handler.h` | 通用 `unique_ptr` 句柄容器 |
| `types.h` | `BlockRef`、`TxRef` 等轻量引用结构 |

### 6.10 `src/init/` —— 各可执行程序的初始化实现

| 文件 | 作用 |
| --- | --- |
| `basic.cpp` | 所有程序共用的"基础环境"初始化（`SetupEnvironment`、`SetupNetworking`） |
| `common.h` / `common.cpp` | 通用初始化：日志参数、日志类别、`-debuglogfile` 等 |
| `bitcoind.cpp` | `bitcoind` 的 `AppInitMain` 实现（守护进程模式） |
| `bitcoin-qt.cpp` | `bitcoin-qt` 单进程 GUI 的 `AppInitMain` |
| `bitcoin-node.cpp` | `bitcoin-node`（IPC 节点进程）的初始化 |
| `bitcoin-gui.cpp` | `bitcoin-gui`（IPC GUI 进程）的初始化 |
| `bitcoin-wallet.cpp` | `bitcoin-wallet` 工具初始化 |

### 6.11 `src/rpc/` —— JSON-RPC 命令实现

| 文件 | 作用 |
| --- | --- |
| `server.h` / `server.cpp` | RPC 框架核心：`CRPCTable` 命令注册、`CRPCCommand` 元数据（参数、权限、类别）、`execute()` 分发、`help` |
| `request.h` / `request.cpp` | 请求解析：JSON → `UniValue` 参数、命名/位置参数、类型检查与错误 |
| `protocol.h` | `JSONRPCRequest` / `JSONRPCReply` 结构（与 `httprpc` 共用） |
| `register.h` | 汇总注册所有 RPC 模块的入口（`RegisterAllCoreRPCCommands`） |
| `server_util.h` / `.cpp` | 从 `NodeContext` 查找链状态、mempool 的辅助（`EnsureChainman` 等） |
| `blockchain.cpp` / `.h` | 链相关：`getblockchaininfo`、`getblock`、`getblockheader`、`gettxout`、`gettxoutsetinfo`、`pruneblockchain`、`verifychain`、`scantxoutset`、`dumptxoutset`/`loadtxoutset`、`getchaintxstats` |
| `mining.cpp` / `.h` | 挖矿：`getblocktemplate`、`submitblock`、`getmininginfo`、`prioritisetransaction`、`getnetworkhashps` |
| `mempool.cpp` / `.h` | mempool：`getrawmempool`、`getmempoolinfo`、`getmempoolentry`、`getmempoolancestors`/`descendants`、`savemempool` |
| `net.cpp` | 网络：`getnetworkinfo`、`getpeerinfo`、`getconnectioncount`、`addnode`、`disconnectnode`、`setban`/`listbanned`、`getnettotals`、`getnodeaddresses` |
| `rawtransaction.cpp` | 原始交易：`getrawtransaction`、`createrawtransaction`、`decoderawtransaction`、`decodescript`、`sendrawtransaction`、`combinerawtransaction`、`signrawtransactionwithkey`、`testmempoolaccept` |
| `rawtransaction_util.h` / `.cpp` | 原始交易构造/解析的共用工具（`ConstructTransaction`、`DecodeHexTx`） |
| `signmessage.cpp` | `signmessage` / `verifymessage`（消息签名，legacy 与 segwit） |
| `txoutproof.cpp` | `gettxoutproof` / `verifytxoutproof`（Merkle 证明） |
| `output_script.cpp` | `deriveaddresses`、`createmultisig`、`validateaddress` 等地址/脚本 RPC |
| `external_signer.cpp` | `enumeratesigners`（外部签名设备） |
| `fees.cpp` | `estimatesmartfee`、`estimaterawfee` |
| `node.cpp` | `getinfo`、`uptime`、`stop`、`logging`、`help`、`getmemoryinfo`、`getindexinfo` |
| `util.h` / `util.cpp` | `RPCHelpMan`（帮助与参数校验框架）、`JSONRPCError`、`AmountFromValue` 等工具 |
| `client.h` / `client.cpp` | RPC 方法名 → 参数元数据表，供 `bitcoin-cli` 做参数转换与检查 |

---

### 6.12 `src/wallet/` —— 钱包模块（可选）

**架构**：`CWallet` 持有 `WalletDatabase`（SQLite 为主，旧 BDB 只读/可迁移）与多组 `ScriptPubKeyMan`（descriptor 钱包由 `DescriptorScriptPubKeyMan` 管理；旧钱包数据由 `LegacyDataSPKM` 承载）。交易构造由 `Spend`/`CoinSelection` 完成，签名通过 `SigningProvider` 抽象，可落到本地私钥或外部签名器。

| 文件 | 作用 |
| --- | --- |
| `wallet.h` / `wallet.cpp` | `CWallet` 核心：密钥管理、交易记录、余额、锁定 coin、通知回调、`AddToWallet`、`CreateTransaction` 入口 |
| `walletdb.h` / `walletdb.cpp` | 钱包数据库抽象：`WalletDatabase`、`DatabaseBatch`、记录读写与 `ReadKeyValue` |
| `db.h` / `db.cpp` | 钱包创建/加载/卸载：`CreateWallet`、`LoadWallet`、`GetWallet`、数据库格式识别 |
| `sqlite.h` / `sqlite.cpp` | SQLite 后端实现（当前默认） |
| `legacybdb.h` / `legacybdb.cpp` | Berkeley DB 旧钱包的只读访问（用于迁移与读取） |
| `migration.h` / `migration.cpp` | BDB → SQLite 钱包迁移 |
| `scriptpubkeyman.h` / `.cpp` | `ScriptPubKeyMan` 抽象与 `DescriptorScriptPubKeyMan`/`LegacyDataSPKM` 实现：地址生成、加密、签名、PSBT 填充 |
| `external_signer_scriptpubkeyman.h` / `.cpp` | 外部签名设备对应的密钥管理器 |
| `crypter.h` / `crypter.cpp` | 私钥加密（AES-256-CBC + 派生密钥），`EncryptWallet`/`Unlock` |
| `spend.h` / `spend.cpp` | 交易构造：选币、找零、费用计算、签名、`CreateTransactionInternal` |
| `coincontrol.h` / `coincontrol.cpp` | `CCoinControl`：用户指定输入、找零地址、避免重用等 |
| `coinselection.h` / `.cpp` | 选币算法：Branch and Bound、SRD、Knapsack，以及费用与废弃币处理 |
| `fees.h` / `fees.cpp` | 钱包费率：`GetMinimumFee`、估算器选择、`FeeCalculation` |
| `feebumper.h` / `.cpp` | `bumpfee`（RBF 提高费用）与 `psbtbumpfee` |
| `receive.h` / `.cpp` | 收款：`GetNewDestination`、支付请求（`Payee`/`CRecipient`） |
| `transaction.h` / `.cpp` | `CWalletTx`：钱包交易包装、状态（确认/冲突/未确认）、`IsMine` 缓存 |
| `types.h` | 钱包公共类型：`WalletFlags`、`isminetype`、`WalletLocation`、`WalletDescriptor` |
| `context.h` / `context.cpp` | `WalletContext`：钱包参数、加载的钱包集合、数据库环境 |
| `init.h` / `init.cpp` | 钱包子系统初始化：解析 `-wallet`、启动时加载、创建默认钱包 |
| `interfaces.h` / `interfaces.cpp` | `interfaces::Wallet` 的钱包侧实现（GUI/IPC 使用） |
| `load.h` / `load.cpp` | `LoadWallet`/`UnloadWallet` 内部流程（线程、回调、失败恢复） |
| `scan.h` / `scan.cpp` | 钱包扫描：`rescanblockchain`、`scanblocks` 的底层实现 |
| `imports.h` / `.cpp` | `importprivkey`、`importwallet`、`importdescriptors`、`importmulti` |
| `dump.h` / `dump.cpp` | `dumpwallet` 文本导出格式 |
| `export.h` / `export.cpp` | 导出钱包 descriptor 信息（`WalletDescInfo`：描述符、创建时间、是否 active、密钥范围） |
| `wallettool.h` / `.cpp` | `bitcoin-wallet` 工具实现（info/dump/create/salvage/migrate） |
| `walletutil.h` / `.cpp` | 钱包元数据读写、`WalletFeature` 兼容性检查 |
| `rpc/wallet.h` / `rpc/*.cpp` | 钱包 RPC 命令集合（见下） |
| `test/` | 钱包单元测试与 fixtures（见 8.1） |

**`wallet/rpc/` 命令分组**

| 文件 | 覆盖的 RPC |
| --- | --- |
| `wallet.cpp` / `wallet.h` | `getwalletinfo`、`listwallets`、`loadwallet`、`createwallet`、`unloadwallet`、`sethdseed`、钱包级帮助 |
| `addresses.cpp` | `getnewaddress`、`getaddressinfo`、`listaddressgroupings`、`setlabel`、`getreceivedbyaddress` |
| `coins.cpp` | `lockunspent`、`listlockunspent`、`listunspent`、`getbalances` |
| `spend.cpp` | `sendtoaddress`、`sendmany`、`send`、`fundrawtransaction`、`walletcreatefundedpsbt`、`sendall`、`bumpfee` |
| `transactions.cpp` | `listtransactions`、`gettransaction`、`listsinceblock`、`abandontransaction`、`rescanblockchain` |
| `encrypt.cpp` | `encryptwallet`、`walletlock`、`walletpassphrase`、`walletpassphrasechange` |
| `backup.cpp` | `backupwallet`、`dumpwallet`、`importwallet` |
| `signmessage.cpp` | `signmessage`（钱包私钥）、`signrawtransactionwithwallet` |

### 6.13 `src/ipc/` —— 多进程 IPC（Cap'n Proto）

**职责**：支持"节点进程与 GUI/钱包进程分离"的部署形态。`bitcoin-node` 运行节点，`bitcoin-gui` 通过 Cap'n Proto RPC 调用节点接口；`bitcoin` 命令加 `--multiprocess` 即可采用该模式。

| 文件 | 作用 |
| --- | --- |
| `interfaces.cpp` | IPC 客户端入口：连接/拉起节点进程、建立协议、Ctrl-C 处理 |
| `process.h` / `process.cpp` | 子进程创建与生命周期管理（`IpcProcess`） |
| `protocol.h` / `protocol.cpp` | 协议抽象：连接建立、消息循环、错误传播 |
| `listen.cpp` | 监听 socket / 连接接受（`ipc::Listen`） |
| `context.h` | IPC 上下文（进程、协议、连接） |
| `exception.h` | IPC 异常类型 |
| `types.h` | IPC 通用类型与句柄 |
| `stub.cpp` | `ENABLE_IPC=OFF` 时的空实现，保证构建 |
| `capnp/common.capnp` / `common-types.h` | 公共类型（金额、哈希、区块头等）的接口定义 |
| `capnp/echo.capnp` / `echo-types.h` | 连通性测试接口 |
| `capnp/init.capnp` / `init-types.h` | 进程初始化接口（创建 Node/Wallet/Mining 等） |
| `capnp/mining.capnp` / `mining.cpp` / `mining-types.h` | 挖矿相关接口（区块模板、提交区块） |
| `capnp/rpc.capnp` / `rpc-types.h` | RPC 客户端接口 |
| `capnp/protocol.h` / `protocol.cpp` | Cap'n Proto 的 message/stream 适配 |
| `test/` | IPC 单元测试（`ipc_test` 库） |
| `libmultiprocess/` | 内置的 libmultiprocess 第三方库：把 C++ 接口自动映射为 Cap'n Proto RPC，并管理多进程生命周期 |

### 6.14 `src/qt/` —— Qt 图形界面（可选）

**结构**：`BitcoinApplication` → `BitcoinGUI`（主窗口）→ `WalletFrame`/`WalletView`（每个钱包一个视图）→ 各 Page/Dialog。数据通过 `ClientModel`（节点数据）与 `WalletModel`（钱包数据）的 Qt Model/View 机制绑定；所有对节点的操作都走 `interfaces::Node`，因此单进程与多进程模式共用同一套 GUI 代码。

| 分组 | 文件 | 作用 |
| --- | --- | --- |
| 应用入口 | `main.cpp`、`bitcoin.cpp/.h`、`initexecutor.cpp/.h` | `BitcoinApplication`、启动参数、`interfaces::Init` 选择（单进程/多进程） |
| 主窗口 | `bitcoingui.cpp/.h`、`walletframe`、`walletview`、`intro`、`splashscreen`、`utilitydialog`、`networkstyle`、`modaloverlay`、`winshutdownmonitor`、`macdockiconhandler.h`、`macnotificationhandler.h`、`macos_appnap.h` | 菜单、工具栏、启动引导、关机拦截、macOS 集成 |
| 节点模型 | `clientmodel.cpp/.h` | 区块高度、连接数、同步进度、网络状态等节点数据源 |
| 钱包模型 | `walletmodel.cpp/.h`、`walletmodeltransaction`、`walletcontroller` | 余额、交易列表、发送交易、钱包加载/创建 |
| 交易视图 | `transactiontablemodel`、`transactionrecord`、`transactiondesc`、`transactiondescdialog`、`transactionfilterproxy`、`transactionview`、`transactionoverviewwidget` | 交易列表、详情、筛选、图表 |
| 页面 | `overviewpage`、`sendcoinsdialog`、`sendcoinsentry`、`sendcoinsrecipient.h`、`receivecoinsdialog`、`receiverequestdialog`、`addressbookpage`、`editaddressdialog` | 总览、发送、接收、地址簿 |
| 高级对话框 | `coincontroldialog`、`coincontroltreewidget`、`psbtoperationsdialog`、`signverifymessagedialog`、`askpassphrasedialog`、`createwalletdialog`、`openuridialog`、`optionsdialog`、`rpcconsole`、`paymentserver` | 选币、PSBT、消息签名、密码、创建钱包、URI、设置、RPC 控制台、BIP70 支付 |
| 通用控件 | `bitcoinamountfield`、`bitcoinunits`、`bitcoinaddressvalidator`、`qvalidatedlineedit`、`qvaluecombobox`、`qrimagewidget`、`guiutil`、`guiconstants.h`、`platformstyle`、`csvmodelwriter`、`freespacechecker`、`notificator` | 金额输入、单位换算、地址校验、二维码、平台样式、CSV 导出、磁盘空间提示、系统通知 |
| 表格模型 | `addresstablemodel`、`recentrequeststablemodel`、`bantablemodel`、`peertablemodel`、`peertablesortproxy` | 地址簿、收款请求、封禁列表、节点列表 |
| 界面文件 | `forms/*.ui` | Qt Designer 布局（overviewpage、sendcoinsdialog、optionsdialog 等 18 个） |
| 资源 | `res/`、`locale/`、`bitcoinstrings.cpp` | 图标/图片、翻译（`.ts`）、翻译字符串表 |
| 测试 | `test/*` | GUI 单元测试与 `test_bitcoin-qt` 入口 |

### 6.15 `src/crypto/` —— 密码学原语

| 文件 | 作用 |
| --- | --- |
| `sha256.h` / `.cpp`（含 `_sse4`、`_avx2`、`_x86_shani`、`_arm_shani`） | SHA-256 及硬件加速实现 |
| `sha1.h` / `.cpp` | SHA-1（仅用于旧格式兼容/测试） |
| `sha3.h` / `.cpp` | SHA-3 / Keccak（用于 MuHash 等） |
| `sha512.h` / `.cpp` | SHA-512 |
| `ripemd160.h` / `.cpp` | RIPEMD-160（生成 P2PKH/P2SH 哈希） |
| `hmac_sha256.h` / `.cpp`、`hmac_sha512.h` / `.cpp` | HMAC |
| `hkdf_sha256_32.h` / `.cpp` | HKDF-SHA256（BIP32 密钥派生） |
| `siphash.h` / `.cpp` | SipHash-2-4（哈希表防碰撞） |
| `chacha20.h` / `.cpp` | ChaCha20 流密码 |
| `poly1305.h` / `.cpp` | Poly1305 MAC |
| `chacha20poly1305.h` / `.cpp` | AEAD（BIP324 传输加密） |
| `aes.h` / `.cpp` | AES 加解密（钱包加密） |
| `ctaes/` | 常量时间 AES 实现（防止侧信道） |
| `muhash.h` / `.cpp` | MuHash3072：可增量更新的多重集哈希（UTXO 集摘要） |
| `common.h` | 通用辅助（内存清洗等） |
| `hex_base.h` / `.cpp` | 十六进制基础编解码 |
| `sha256_*`、`sha512_*` 及 `crypto_tests` | 各算法实现与测试向量 |

### 6.16 `src/util/` —— 通用基础设施

**原则**：不包含比特币业务类型、不依赖全局状态，任何层都可复用；错误处理统一使用 `util::Expected`（低层）与 `util::Result`（高层）。

| 文件 | 作用 |
| --- | --- |
| `check.h` / `check.cpp` | `Assert()`、`CHECK_NONFATAL()`：内部不变量校验 |
| `expected.h` / `expected.cpp`、`result.h` | `Expected<T,E>` / `Result<T>`：错误传播的两种标准形态 |
| `exception.h` / `.cpp` | 异常基类 |
| `fs.h` / `fs.cpp`、`fs_helpers.h` / `.cpp` | 文件系统（`std::filesystem` 封装）、原子写入、目录锁 |
| `readwritefile.h` / `.cpp` | 简单文件读写（配置、cookie） |
| `thread.h` / `.cpp`、`threadinterrupt.h` / `.cpp`、`threadnames.h` / `.cpp`、`threadpool.h` | 线程、可中断睡眠、线程命名、线程池 |
| `time.h` / `.cpp`、`timer.h`（在 logging/） | 时间类型、`SteadyClock`、格式化 |
| `sync` 相关 | `stdmutex.h`（标准互斥包装）、`task_runner.h`（任务执行抽象） |
| `sock.h` / `sock.cpp`、`netif.h` | Socket 封装、网络接口枚举（`netif` 实际在 `common/`） |
| `strencodings.h` / `.cpp`、`string.h` / `.cpp` | 十六进制/Base64 编解码、字符串工具（`TrimString`、`SplitString`、`ToString`） |
| `moneystr.h` / `.cpp` | 金额与字符串互转（BTC 小数格式） |
| `fees.h` / `.cpp` | `FeeEstimateMode`、`FeeReason` 等费率枚举 |
| `feefrac.h` / `.cpp` | `FeeFrac`：精确费率分数与比较（cluster mempool 使用） |
| `rbf.h` / `.cpp` | `SignalsOptInRBF()`（BIP125 信号判断） |
| `asmap.h` / `.cpp` | ASMap 解析与 IP→AS 查询 |
| `bip32.h` / `.cpp` | BIP32 扩展密钥与派生路径 |
| `bytevectorhash.h` / `.cpp` | 字节向量的 SipHash 哈希器 |
| `byte_units.h` | 字节单位（KiB/MiB）格式与解析 |
| `bitset.h`、`bitdeque.h`、`vecdeque.h`、`vector.h`、`insert.h`、`any.h` | 容器与类型工具（紧凑位集、双端队列、`Vector()` 构造、`util::Any`） |
| `fastrange.h` | 快速取模（`FastRange32/64`） |
| `golombrice.h` | Golomb-Rice 编解码（BIP158 过滤器） |
| `hasher.h` / `.cpp`、`hash_type.h` | 通用哈希器与哈希类型标记 |
| `overloaded.h`、`overload` 宏 | 访问者模式辅助 |
| `not_null.h` | `NotNull<T>` 智能指针 |
| `obfuscation.h` | 网络地址混淆（`AddrMan` 反探测） |
| `overflow.h` | 整数溢出检查 |
| `insert.h` | 容器插入辅助 |
| `log.h` | 轻量日志宏（供不能依赖 `logging.h` 的底层代码） |
| `macros.h` | 通用宏（`DISABLE_COPY_AND_ASSIGN` 等） |
| `serfloat.h` / `.cpp` | 浮点数的确定性序列化 |
| `signalinterrupt.h` / `.cpp`、`btcsignals.h` | 中断信号处理、轻量信号/槽（替代 boost::signals2） |
| `tokenbucket.h`、`tokenpipe.h` / `.cpp` | 令牌桶限速、令牌管道 |
| `batchpriority.h` / `.cpp` | 把线程设为内核批处理优先级 |
| `subprocess.h`、`exec.h` / `.cpp` | 子进程执行（外部签名器、`bitcoin` 命令转发） |
| `syserror.h` / `.cpp` | 系统错误码转字符串 |
| `trace.h` | USDT 追踪点宏 |
| `translation.h` | 国际化（`_()`、`bilingual_str`） |
| `types.h` | 通用小类型 |
| `ui_change_type.h` | UI 变更类型（配置变更标记） |
| `chaintype.h` / `.cpp` | `ChainType` 枚举（MAIN/TESTNET/SIGNET/REGTEST） |
| `bytevectorhash`、`sock` 已列 | |

### 6.17 `src/bench/` —— 微基准

`bench.h` / `bench.cpp` 提供 `BENCHMARK` 宏与计时框架，`bench_bitcoin.cpp` 为入口（支持 `-sanity-check`、过滤名称）。基准文件按模块命名，例如：

| 主题 | 代表文件 |
| --- | --- |
| 区块与验证 | `checkblock`、`connectblock`、`verify_script`、`block_assemble`、`checkblockindex` |
| mempool / cluster | `mempool_stress`、`mempool_eviction`、`mempool_ephemeral_spends`、`txgraph`、`cluster_linearize`、`disconnected_transactions` |
| 网络 | `addrman`、`peer_eviction`、`bip324_ecdh`、`ellswift` |
| 脚本与钱包 | `sign_transaction`、`descriptors`、`coin_selection`、`wallet_*` |
| 密码学与序列化 | `crypto_hash`、`chacha20`、`poly1305`、`gcs_filter`、`streams_findbyte`、`prevector`、`uint256_blob` |
| 其它 | `asmap`、`base58`、`bech32`、`bip352`、`logging`、`rpc_blockchain`、`rpc_mempool` |

### 6.18 `src/test/` —— 单元测试与 fuzz

| 子目录/文件 | 作用 |
| --- | --- |
| `test/` 根目录 | 约 140 个 `*_tests.cpp`，每个对应一个模块（`validation_tests`、`mempool_tests`、`script_tests`、`net_tests`、`wallet` 除外）；`main.cpp` 是 `test_bitcoin` 入口 |
| `test/util/` | 测试基础设施：`setup_common.h`（`TestingSetup`/`ChainTestingSetup`）、`chainstate.h`、`transaction_utils`、`script.h`、`net.h`、`json.h`、`logging.h`、`coverage.h`、`mining.h`、`txmempool.h` |
| `test/kernel/` | 内核库测试（`test_kernel.cpp` 与测试用区块数据） |
| `test/data/` | 测试向量（密钥、脚本、交易、区块等） |
| `test/fuzz/` | 143 个 fuzz target；`fuzz.h` 定义 `FUZZ_TARGET` 注册机制，`FuzzedDataProvider.h` 提供输入切分；覆盖共识、脚本、P2P 消息、RPC 解析、钱包、序列化、第三方库等 |

---

## 7. 内置第三方库

| 目录 | 版本/来源 | 许可证 | 作用 | 使用者 |
| --- | --- | --- | --- | --- |
| `src/secp256k1/` | libsecp256k1 0.8.1 | MIT | 椭圆曲线运算：ECDSA、Schnorr（BIP340）、ECDH、EllSwift（BIP324）、MuSig2 模块 | `bitcoin_consensus`、`bitcoin_common` |
| `src/leveldb/` | Google LevelDB（内置快照，含 Bitcoin 定制补丁） | BSD-3-Clause | 嵌入式键值数据库 | UTXO（`CCoinsViewDB`）、区块索引、索引器、钱包（BDB 之外的元数据） |
| `src/univalue/` | Bitcoin Core 维护的 JSON 库 | MIT | JSON 解析/生成 | RPC、`settings.json`、`bitcoin-cli` |
| `src/minisketch/` | sipa/minisketch | MIT | 集合调和（sketch） | Erlay 交易中继（`node/txreconciliation`） |
| `src/crc32c/` | Google CRC32C（含 ARM64/SSE4.2 加速） | BSD-3-Clause | CRC32C 校验 | LevelDB（`cmake/crc32c.cmake` 引入，`leveldb` 链接 `crc32c`） |

说明：

1. 这些库以**源码子树**形式内置，保证可复现构建；部分可通过系统库替换（`depends/` 或 CMake 查找）。
2. `src/ipc/libmultiprocess/` 也是内置第三方库，用于把 C++ 接口自动生成 Cap'n Proto RPC。
3. `src/qt/locale/` 是翻译数据，不属于第三方代码。

---

## 8. 测试与质量保障体系

| 层次 | 位置 | 运行方式 | 覆盖内容 |
| --- | --- | --- | --- |
| 单元测试 | `src/test/*_tests.cpp` | `ctest --test-dir build` 或 `./build/bin/test_bitcoin --run_test=...` | 每个模块的函数级正确性 |
| 内核测试 | `src/test/kernel/` | 随 `BUILD_KERNEL_TEST` 构建 | `libbitcoinkernel` API |
| 钱包测试 | `src/wallet/test/` | ctest | 选币、数据库、PSBT、迁移、加密 |
| GUI 测试 | `src/qt/test/` | `test_bitcoin-qt` | 地址簿、URI、钱包、RPC 嵌套调用 |
| 功能/集成测试 | `test/functional/`（289 个 `.py`） | `build/test/functional/test_runner.py`（可加 `--jobs`） | 多节点组网、分叉、RPC、钱包、P2P、mempool、挖矿等端到端行为 |
| fuzz | `src/test/fuzz/` | 构建 `BUILD_FUZZ_BINARY=ON` 后运行 `fuzz <target>`；`test/fuzz/test_runner.py` 批量执行 | 解析器、脚本、P2P 消息、RPC、共识、序列化 |
| 微基准 | `src/bench/` | `BUILD_BENCH=ON`，运行 `bench_bitcoin` | 性能回归 |
| 静态检查 | `test/lint/` | `test/lint/test_runner`（CI 中运行） | include guard、循环依赖、文件命名、Python/shell 风格、翻译、文档、subtree 一致性 |
| 消毒器 | CI 配置 | ASan/TSan/MSan/UBSan/Valgrind 构建 | 内存与并发错误 |
| 可复现构建 | `contrib/guix/` | `guix-build` | 二进制与源码一致性 |

功能测试框架（`test/functional/test_framework/`）提供 `BitcoinTestFramework`、`TestNode`（启动/停止节点、RPC 封装）、`MiniWallet`、区块生成工具等，是理解节点外部行为的最佳材料。

---

## 9. 关键流程与调用链

### 9.1 启动流程

```
main()                                    src/bitcoind.cpp
 └─ SetupEnvironment / SetupNetworking    src/init/basic.cpp
 └─ AppInitMain()                         src/init/bitcoind.cpp → src/init.cpp
     ├─ 参数解析（ArgsManager）            src/common/args.cpp
     ├─ 日志初始化                        src/logging.cpp、src/init/common.cpp
     ├─ EvalScript 注册                   src/script/interpreter.cpp
     ├─ 加载链状态（可选 reindex/快照）    src/node/chainstate.cpp、src/validation.cpp
     ├─ 初始化 mempool 与持久化            src/txmempool.cpp、src/node/mempool_persist.cpp
     ├─ 初始化索引                        src/node/indexes.cpp、src/index/*.cpp
     ├─ 初始化 P2P（监听/连接/DNS 种子）   src/net.cpp、src/net_processing.cpp
     ├─ 初始化 RPC/REST/HTTP              src/httprpc.cpp、src/httpserver.cpp、src/rest.cpp
     ├─ 初始化 ZMQ（可选）                src/zmq/zmqnotificationinterface.cpp
     ├─ 加载钱包（可选）                  src/wallet/init.cpp
     └─ 启动调度器与各线程
 └─ WaitForShutdown()                     src/init.cpp
```

### 9.2 区块从 P2P 到落盘

```
CConnman 收到 "block"/"cmpctblock"
  → PeerManager::ProcessMessage           src/net_processing.cpp
  → ProcessNewBlock / ProcessNewBlockHeaders   src/validation.cpp
  → CheckBlock（结构/PoW/merkle）           src/consensus/validation.h、src/pow.cpp
  → AcceptBlock（写入 blk/rev、更新索引）   src/validation.cpp、src/node/blockstorage.cpp
  → ActivateBestChain（可能触发重组）       src/validation.cpp
  → ConnectBlock（逐笔验证输入、更新 UTXO） src/validation.cpp、src/coins.cpp
  → FlushStateToDisk（周期性）              src/validation.cpp、src/txdb.cpp
  → ValidationSignals 广播区块连接事件      src/validationinterface.cpp
      → 钱包 / 索引 / ZMQ 订阅者
```

### 9.3 交易从 P2P 到 mempool

```
"inv"/"tx"/"cmpctblock" → PeerManager::ProcessMessage
  → TxDownloadManager 决定是否请求          src/node/txdownloadman_impl.cpp
  → TX 消息到达 → ProcessTransaction
  → MemPoolAccept::Submit（预检 + 脚本 + 费率 + RBF）  src/validation.cpp、src/policy/rbf.cpp
  → CTxMemPool::addUnchecked（更新祖先/后代统计、TxGraph）
  → ValidationSignals::TransactionAddedToMempool
  → 转发公告（inv / 私有广播）
```

### 9.4 出块

```
RPC getblocktemplate 或内部 miner
  → BlockTemplateManager::CreateNewBlock    src/node/block_template_manager.cpp
  → BlockAssembler 选择交易（按 chunk 费率） src/node/miner.cpp、src/txgraph.cpp
  → 计算 coinbase、witness commitment
  → 外部矿工计算 PoW → submitblock
  → ProcessNewBlock → 9.2 的验证流程
```

### 9.5 钱包交易

```
GUI/RPC send
  → CWallet::CreateTransaction              src/wallet/spend.cpp
  → CoinSelection（BNB/SRD/Knapsack）        src/wallet/coinselection.cpp
  → 估算费率、找零、签名（SigningProvider）  src/wallet/fees.cpp、src/script/sign.cpp
  → CWallet::CommitTransaction → BroadcastTransaction   src/node/transaction.cpp
  → mempool 准入（9.3）
```

### 9.6 RPC 调用

```
HTTP 请求 → HTTPWorkQueue → httprpc 解析/认证
  → CRPCTable::execute("getblockchaininfo")   src/rpc/server.cpp
  → 对应 RPCHelpMan 处理函数                  src/rpc/blockchain.cpp
  → 通过 NodeContext 访问 chainman/mempool
  → UniValue 响应 → JSON 输出
```

---

## 10. 运行时数据目录（`~/.bitcoin/`）

| 路径 | 内容 | 相关代码 |
| --- | --- | --- |
| `blocks/blkNNNNN.dat` | 区块原始数据（按 128 MiB 分文件） | `src/node/blockstorage.cpp`、`src/flatfile.cpp` |
| `blocks/revNNNNN.dat` | 区块 undo 数据（回滚用） | 同上、`src/undo.h` |
| `blocks/index/` | 区块索引 LevelDB | `src/txdb.cpp`（`CBlockTreeDB`） |
| `chainstate/` | UTXO 集 LevelDB（`coins` 表、`flag` 等） | `src/txdb.cpp`、`src/coins.cpp` |
| `chainstate_snapshot/` | assumeutxo 背景链状态 | `src/node/utxo_snapshot.cpp` |
| `indexes/txindex/`、`indexes/blockfilter/`、`indexes/coinstats/`、`indexes/txospender/` | 各可选索引数据库 | `src/index/*` |
| `mempool.dat` | mempool 持久化快照 | `src/node/mempool_persist.cpp` |
| `peers.dat` | 地址管理器数据 | `src/addrdb.cpp` |
| `banlist.json` | 封禁列表 | `src/addrdb.cpp` |
| `settings.json` | 运行时设置（如 `-settings` 持久化） | `src/common/settings.cpp` |
| `bitcoin.conf` | 配置文件 | `src/common/args.cpp`、`src/common/config.cpp` |
| `.cookie` | RPC 临时认证 cookie | `src/rpc/request.cpp`、`src/httprpc.cpp` |
| `wallets/<name>/wallet.dat` 或 `wallet.sqlite` | 钱包数据库 | `src/wallet/db.cpp`、`src/wallet/sqlite.cpp` |
| `debug.log` | 日志 | `src/logging.cpp` |
| `blocks/xor.dat` | 对 blk/rev 数据做滚动 XOR 的混淆密钥（防误判文件类型/防扫描） | `src/node/blockstorage.cpp`；`doc/files.md` 有说明 |

参考 `doc/files.md` 获取官方描述。

---

## 11. 推荐阅读路线

### 11.1 想理解"比特币如何工作"

1. `src/primitives/transaction.h`、`src/primitives/block.h` —— 数据结构。
2. `src/consensus/tx_check.cpp`、`src/consensus/tx_verify.cpp` —— 交易合法性。
3. `src/script/interpreter.cpp` —— 脚本执行（重点看 `EvalScript` 与 `VerifyScript`）。
4. `src/validation.cpp` —— `ConnectBlock`/`ActivateBestChain`（最核心的 2000 行）。
5. `src/coins.cpp`、`src/txdb.cpp` —— UTXO 模型。
6. `src/pow.cpp`、`src/chainparams.cpp` —— 共识参数与难度。
7. `src/txmempool.cpp`、`src/policy/policy.cpp` —— 中继策略。

### 11.2 想做节点/网络开发

1. `src/net.cpp`、`src/net_processing.cpp` —— P2P。
2. `src/protocol.h`、`src/netaddress.h`、`src/addrman.h`。
3. `src/node/txdownloadman_impl.cpp`、`src/txrequest.cpp` —— 交易下载。
4. `src/bip324.cpp` —— v2 加密传输。
5. `doc/reduce-traffic.md`、`doc/p2p-bad-ports.md`。

### 11.3 想做钱包/应用开发

1. `src/wallet/wallet.h`、`src/wallet/spend.cpp`。
2. `src/wallet/scriptpubkeyman.h`、`src/script/descriptor.cpp`。
3. `src/wallet/coinselection.cpp`、`src/wallet/fees.cpp`。
4. `src/psbt.h`、`src/rpc/*`。
5. `doc/descriptors.md`、`doc/psbt.md`、`doc/managing-wallets.md`。

### 11.4 想集成/嵌入

1. `src/kernel/bitcoinkernel.h` + `src/kernel/bitcoinkernel_wrapper.h`。
2. `doc/design/libraries.md`。
3. `src/interfaces/node.h`、`src/ipc/capnp/*.capnp`。

---

## 12. 术语表

| 术语 | 含义 |
| --- | --- |
| UTXO | 未花费交易输出，比特币的账户模型基础 |
| mempool | 节点本地未确认交易池 |
| cluster / chunk | cluster mempool 中通过依赖连通的交易集合 / 线性化后按费率切分的打包单元 |
| RBF | Replace-By-Fee，用更高手续费替换未确认交易（BIP125） |
| TRUC / v3 | Topologically Restricted Until Confirmation，限制未确认后代数量的交易策略（BIP431） |
| CPFP | Child Pays For Parent，子交易补贴父交易费率 |
| PSBT | Partially Signed Bitcoin Transaction（BIP174/371） |
| descriptor | 可读、可组合的输出脚本描述语言（BIP380-386） |
| Miniscript | 可分析的脚本策略语言 |
| assumeutxo | 通过可信 UTXO 快照快速启动，后台再验证历史 |
| Erlay | 基于集合调和的低带宽交易中继（BIP330） |
| ASMap | IP 地址到自治系统（AS）的映射，用于抗女巫 |
| IPC | 进程间通信，此处特指 Cap'n Proto 多进程架构 |
| bitcoinkernel | 可嵌入的共识内核库 |
| Coinbase | 区块中的矿工奖励交易（含补贴与手续费） |
| Undo 数据 | 区块断开时恢复 UTXO 所需的被花费输出记录 |

---

## 附录 A：文件速查索引

| 想找什么 | 去哪里 |
| --- | --- |
| 某个 RPC 的实现 | `src/rpc/*.cpp`、`src/wallet/rpc/*.cpp` |
| 某个命令行参数 | `src/common/args.cpp`、`src/init.cpp`、各模块 `*_args.cpp` |
| 共识常量 | `src/consensus/params.h`、`src/consensus/consensus.h`、`src/chainparams.cpp` |
| 错误提示文本 | `src/util/translation.h`、`src/common/messages.cpp` |
| 日志类别 | `src/logging.h`（`LogCategory` 枚举） |
| 序列化格式 | `src/serialize.h`、`src/primitives/*.h` |
| 网络 magic 与端口 | `src/kernel/messagestartchars.h`、`src/chainparams.cpp` |
| 脚本 opcode | `src/script/script.h`、`src/script/script.cpp` |
| 钱包数据库 schema | `src/wallet/walletdb.cpp`、`src/wallet/sqlite.cpp` |
| 索引实现 | `src/index/*.cpp` |
| 测试写法示例 | `src/test/*_tests.cpp`、`test/functional/*.py` |

## 附录 B：本文档的核查说明

- 目录与文件清单来自实际 `ls`/`find` 结果，覆盖 `src/` 顶层全部代码文件与全部子目录。
- 库的归属与可执行产物来自 `CMakeLists.txt`、`src/*/CMakeLists.txt` 的 `add_library`/`add_executable` 声明。
- 版本号、构建开关来自顶层 `CMakeLists.txt`。
- 标注"（推断）"的条目未能直接由代码注释确认，建议以对应源码为准。
- 第三方库版本（secp256k1 0.8.1）来自其 `CMakeLists.txt`；LevelDB/minisketch 的具体上游版本随子树提交而定。



