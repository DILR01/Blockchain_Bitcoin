# =============================================================================
# Ditcoin —— 独立实验链（参数 + 共识规则级新链）
#
# 构建约定：
#   * 主体严格 C11（CMAKE_C_EXTENSIONS=OFF，禁止 GNU 扩展 / VLA）
#   * 默认开启 -Wall -Wextra -Wpedantic -Werror（零告警是硬约束）
#   * 可选 Sanitizer：-DDTC_SANITIZE=address,undefined（CI 使用）
#
# 常用命令：
#   cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
#   cmake --build build -j
#   ctest --test-dir build --output-on-failure
# =============================================================================
cmake_minimum_required(VERSION 3.16)

project(ditcoin
        VERSION 0.1.0
        DESCRIPTION "Ditcoin: an independent experimental blockchain"
        LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "构建类型" FORCE)
endif()

# -----------------------------------------------------------------------------
# 编译选项
#
# -D_POSIX_C_SOURCE=200809L：只为拿 clock_gettime / gmtime_r 等 POSIX 接口，
# 不引入 GNU 扩展；若需要更严格可换 C11 timespec_get。
# -----------------------------------------------------------------------------
add_library(dtc_flags INTERFACE)
target_compile_definitions(dtc_flags INTERFACE _POSIX_C_SOURCE=200809L)
target_compile_options(dtc_flags INTERFACE
    -Wall -Wextra -Wpedantic -Werror
    -Wshadow -Wconversion -Wsign-conversion
    -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Wundef)

# -----------------------------------------------------------------------------
# Sanitizer（CI 用）：-DDTC_SANITIZE=address,undefined
# -----------------------------------------------------------------------------
set(DTC_SANITIZE "" CACHE STRING "启用 Sanitizer，例如 address,undefined")
if(DTC_SANITIZE)
    add_compile_options(-fsanitize=${DTC_SANITIZE} -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=${DTC_SANITIZE})
endif()

# -----------------------------------------------------------------------------
# vendored libsecp256k1（ECDSA 验签）
#
# 提示词硬约束 2：签名算法一律使用 vendored libsecp256k1，禁止自研。
# 源码来自 vendor/secp256k1（0.8.1，MIT），只启用需要的模块：
#   recovery / ecdh / extrakeys / schnorrsig / ellswift
# 关闭其自带 tests/benchmark/ctime，避免拖慢本项目 CI。
# -----------------------------------------------------------------------------
option(DTC_WITH_SECP256K1 "启用 vendored libsecp256k1 做 ECDSA 验签" ON)

if(DTC_WITH_SECP256K1)
    set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(SECP256K1_INSTALL OFF CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_ECDH ON CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
    set(SECP256K1_ENABLE_MODULE_ELLSWIFT ON CACHE BOOL "" FORCE)
    add_subdirectory(vendor/secp256k1)
endif()

# -----------------------------------------------------------------------------
# 核心静态库 dtc_core
#
# 目标分层（严格单向依赖，当前仅落地 M0/M1）：
#   dtc_core = crypto(glue) + util + consensus + primitives + script + secp
#   后续模块（kernel/policy/mempool/net/wallet/iface/qt）按 SPEC 追加。
# -----------------------------------------------------------------------------
add_library(dtc_core STATIC
    # --- M0：密码学胶水层 ---
    src/crypto/sha256.c
    src/crypto/sha512.c
    src/crypto/ripemd160.c
    src/crypto/sha1.c
    src/crypto/hash.c
    src/crypto/hmac.c
    src/crypto/hkdf.c
    src/crypto/siphash.c
    src/crypto/base58.c
    src/crypto/bech32.c
    # --- 通用工具 ---
    src/uint256.c
    src/amount.c
    src/reader.c
    src/hex.c
    # --- M1：共识核心 ---
    src/consensus/params.c
    src/consensus/economics.c
    src/consensus/lwma.c
    src/consensus/pow.c
    src/consensus/merkle.c
    src/consensus/genesis.c
    # --- 链原语与脚本 ---
    src/primitives/tx.c
    src/primitives/block.c
    src/script/script.c
    src/script/sighash.c
)

target_include_directories(dtc_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(dtc_core PUBLIC dtc_flags)

if(DTC_WITH_SECP256K1)
    target_sources(dtc_core PRIVATE src/secp/ecdsa.c)
    target_compile_definitions(dtc_core PUBLIC DTC_HAVE_SECP256K1=1)
    target_include_directories(dtc_core PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/vendor/secp256k1/include)
    target_link_libraries(dtc_core PUBLIC secp256k1)
endif()

# -----------------------------------------------------------------------------
# 工具：创世块构建/挖矿
#
# Ditcoin 创世块按规范「自挖」，本工具用于离线挖出 nonce 并输出可冻结的
# hash / 头字段。未挖矿时 params.c 中的 DTC_GENESIS_NONCE 为 0 占位。
# -----------------------------------------------------------------------------
add_executable(dtc-genesis tools/dtc_genesis.c)
target_link_libraries(dtc-genesis PRIVATE dtc_core)

# -----------------------------------------------------------------------------
# 测试：单一可执行文件聚合三层测试（向量 / 自洽 / 隔离）
# -----------------------------------------------------------------------------
add_executable(dtc_tests
    tests/test_main.c
    tests/test_crypto.c
    tests/test_uint256.c
    tests/test_reader.c
    tests/test_params.c
    tests/test_economics.c
    tests/test_lwma.c
    tests/test_pow.c
    tests/test_merkle.c
    tests/test_primitives.c
    tests/test_script.c
    tests/test_isolation.c
)
target_link_libraries(dtc_tests PRIVATE dtc_core)
target_include_directories(dtc_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

enable_testing()
add_test(NAME dtc_tests COMMAND dtc_tests)
