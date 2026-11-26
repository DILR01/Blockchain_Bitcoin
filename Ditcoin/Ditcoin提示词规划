# Ditcoin 提示词规划（修订版）

【角色】资深 C11 系统工程师 + 区块链协议实现者。

【项目】Ditcoin —— 一条全新的独立区块链。继承比特币思想（UTXO/PoW/脚本/P2P），
但拥有自己的创世块、网络身份、共识参数与经济模型。
★ 不兼容 Bitcoin：不接入其网络、不共享地址格式、不与其钱包/工具互操作。
★ "最小" = 功能面完整（P2P/全验证/mempool/钱包+接口），规模最小（局域网多节点跑通）。

【定位澄清 — 写入 README 顶部】
Ditcoin 是「参数 + 共识规则级新链」，与 Litecoin / Dogecoin 同档：
  ✓ 独立创世块、独立 UTXO 集、独立网络身份/地址/密钥派生域
  ✓ 实质共识创新：LWMA-1 难度、时间戳锚点约束、64字节交易禁令、
                  coinbase nLockTime 唯一性、尾排放经济模型
  ✗ 沿用 Bitcoin：UTXO 模型、Script 全集、SHA256d PoW、cluster mempool 架构、
                  descriptor+BIP32+PSBT 钱包模型
它不是 Bitcoin 的分叉（不共享其历史），也不是架构级新系统（如 Monero RingCT）。

【硬约束】
1. 主体 C11（-std=c11，无 VLA、无 GNU 扩展）；仅 Qt GUI 用 C++ 薄壳 + extern "C"。
2. ECDSA/Schnorr 一律用 vendored libsecp256k1（开启 recovery/ecdh/extrakeys/
   schnorrsig/ellswift），禁止自己写签名算法。
3. 所有链参数集中在 dtc_consensus/params.c，其余文件禁止裸魔数（CI 检查）。
4. node/wallet/gui 互不引用符号，只通过 dtc_interfaces.h 的函数指针 vtable 通信。
5. GUI 进程禁止链接 kernel；wallet 禁止依赖 kernel。
6. 构建 CMake；CI 全程 ASan/UBSan/TSan + libFuzzer。
7. README 顶部标注：独立实验链，代币无价值，勿转入真实资产。
8. 密码学策略：vendor 成熟实现（不改）+ 自研仅做胶水（必须 fuzz）。详见 M0 与 vendor 清单。
9. 项目许可证：MIT（与所有 vendored 组件兼容）。SPEC 中逐项核对 vendor 许可证。

════════ 第一步：生成 params.c（全部数值已实测复核，直接用）════════

/* ---- A 链身份 ---- */
MAGIC_MAIN      = 0x44495443   /* "DITC" */
MAGIC_TEST      = 0x44495454
MAGIC_REG       = 0x44495452
P2P_PORT        = 28333 ; RPC_PORT = 28332
TEST_P2P        = 38333 ; TEST_RPC = 38332
HRP_MAIN        = "dtc" ; HRP_TEST = "tdtc"
HD_PUB_VERSION  = 0xadc9ce9c   /* → dtpub... 已验证前缀稳定 */
HD_PRV_VERSION  = 0xadc9ca62   /* → dtprv... 已验证前缀稳定 */
P2PKH_VERSION   = 0x1e (30)    /* → D... */
P2SH_VERSION    = 0x3f (63)    /* → S... */
WIF_VERSION     = 0x7a (122)   /* → K/L... */
PSBT_MAGIC      = "dtpb\xff"   /* 64747062ff, 5 bytes */
SNAPSHOT_MAGIC  = "dtxo\xff"   /* 6474786fff, 5 bytes */
V2_HKDF_SALT    = "ditcoin_v2_shared_secret" || MAGIC
HD_SEED_TAG     = "Ditcoin seed"
BIP44_COIN_TYPE = 0xD17C0DE    /* 自有，非 0 */
UNIT: 1 DTC = 100000000 dts (ditoshi)

/* ---- B 共识 ---- */
BLOCK_INTERVAL T   = 600 s
DAA                = LWMA-1 (target form), N = 45, 逐块调整
MAX_BLOCK_WEIGHT   = 4000000 ; WITNESS_SCALE = 4 ; MAX_SIGOPS_COST = 80000
COINBASE_MATURITY  = 100
MTP_WINDOW         = 11
FTL                = 1800 s    /* 用节点本地时间，禁用 peer median time */
ANCHOR_PERIOD      = 2016      /* 仅用于时间戳约束，不用于难度 */
TIMEWARP_GRACE     = 7200 s
BAN_64BYTE_TX      = true
COINBASE_LOCKTIME  = height - 1 ; COINBASE_SEQ != 0xffffffff
POW_LIMIT          = 00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
历史激活高度        = 无（全部规则从高度 0 生效）
历史例外块          = 无
BIP30 重复检查      = 不做（由 coinbase nLockTime 保证唯一）

/* ---- B2 经济模型：尾排放（★与 Bitcoin 本质不同，非等价变换）---- */
INITIAL_SUBSIDY     = 2500000000        /* 25 DTC */
HALVING_INTERVAL    = 420000
TAIL_EMISSION_FLOOR = 50000000          /* 0.5 DTC，永久 */
HALVING_COUNT       = 6                 /* 推导值，用于断言 */
TAIL_START_HEIGHT   = 2520000           /* = 6 × 420000 */
PRE_TAIL_SUPPLY     = 2067187500000000  /* 20,671,875.00 DTC */
BLOCKS_PER_YEAR     = 52560
TAIL_ANNUAL_DTS     = 2628000000000     /* 26,280 DTC/年 */
★ 删除 MAX_MONEY 作为共识上界的用法，改用 supply_at(h) 单调函数

subsidy 函数（纯整数，已实测）：
  int64_t dtc_subsidy(int32_t height) {
      uint32_t h = (uint32_t)(height / HALVING_INTERVAL);
      int64_t  s = (h >= 63) ? 0 : (INITIAL_SUBSIDY >> h);
      return s > TAIL_EMISSION_FLOOR ? s : TAIL_EMISSION_FLOOR;
  }

supply_at 闭式解（已与逐块累加对拍一致）：
  int64_t dtc_supply_at(int64_t height) {   /* 已挖出 0..height-1 块的总发行 */
      if (height <= 0) return 0;
      if (height <= TAIL_START_HEIGHT) {
          int64_t total=0, s=INITIAL_SUBSIDY, rem=height;
          while (rem > 0) {
              int64_t take = rem < HALVING_INTERVAL ? rem : HALVING_INTERVAL;
              total += s*take; rem -= take; s >>= 1;
              if (s < TAIL_EMISSION_FLOOR) s = TAIL_EMISSION_FLOOR;
          }
          return total;
      }
      return PRE_TAIL_SUPPLY + (height - TAIL_START_HEIGHT)*TAIL_EMISSION_FLOOR;
  }

完整补贴表（写入 SPEC，逐行断言）：
  高度 [      0,  420000)  → 25.00000 DTC
  高度 [ 420000,  840000)  → 12.50000 DTC
  高度 [ 840000, 1260000)  →  6.25000 DTC
  高度 [1260000, 1680000)  →  3.12500 DTC
  高度 [1680000, 2100000)  →  1.56250 DTC
  高度 [2100000, 2520000)  →  0.78125 DTC
  高度 [2520000,      ∞)  →  0.50000 DTC  ← 永久，不再减半

关键指标（已核对）：
  减半阶段 47.95 年，累计 20,671,875.00 DTC
  尾排放年增 26,280 DTC
  第 50 年 20,725,875 DTC (通胀 0.12680%)
  第100年 22,039,875 DTC (通胀 0.11924%)
  第200年 24,667,875 DTC (通胀 0.10654%)
  第1000年 45,691,875 DTC (通胀 0.05752%)
  ⇒ 无硬上限，通胀率单调趋零但永不为零，矿工永远有区块补贴保底

/* ---- B3 sighash 域分离开关（★补丁1）---- */
#define DTC_SIGHASH_DOMAIN_SEP 0   /* 0=沿用原算法(默认) 1=前置MAGIC */
  static void sighash_hash(const uint8_t *buf, size_t len, uint8_t out[32]) {
  #if DTC_SIGHASH_DOMAIN_SEP
      dtc_sha256d_2parts(MAGIC_MAIN_LE, 4, buf, len, out);
  #else
      dtc_sha256d(buf, len, out);
  #endif
  }
  实测：sep=0 → 852c98044fb00507... ; sep=1 → 9822997af65ff519...

/* ---- B4 PoW 抽象（★补丁3）---- */
typedef struct {
    const char *name;
    void   (*hash)(const uint8_t *hdr, size_t len, uint8_t out[32]);
    size_t (*scratch_bytes)(void);   /* SHA256d=0, Scrypt=1MB */
} dtc_pow_algo_t;
extern const dtc_pow_algo_t dtc_pow_sha256d;   /* 默认 */
POW_ALGO      = &dtc_pow_sha256d
POW_HASH_NAME = "sha256d"    /* 写入 getblockchaininfo 供运维识别 */
/* 预留 dtc_pow_scrypt / dtc_pow_auxpow，切换只需改此处 + 重挖创世 */

/* ---- C 策略（非共识，Ditcoin 自选）---- */
MIN_RELAY_FEE = 100 dts/kvB ; INCREMENTAL_FEE = 100
DUST_RATE = 3000 ; BYTES_PER_SIGOP = 20 ; MEMPOOL_MAX = 300 MB
CLUSTER_LIMIT = 64 笔 ; CLUSTER_SIZE = 101 kvB
TRUC_PARENT_VSIZE = 10000 ; TRUC_CHILD_VSIZE = 1000
PKG_MAX_COUNT = 25 ; PKG_MAX_WEIGHT = 404000 ; MAX_CONFLICT_CLUSTERS = 100

/* ---- D 创世块 ---- */
自挖：coinbase scriptSig = OP_0 + push("Ditcoin genesis <date> anti-premine: <公开事件>")
      输出 = 0 金额 + OP_RETURN（零预挖）；nVersion=1；hashPrevBlock=0
      挖出后把 hash 写死进 params.c 与单元测试。换 PoW 算法必须重挖。

════════ 第二步：目录树 + CMakeLists + dtc_interfaces.h ════════

分层（严格单向依赖）：
dtc_crypto    ← 无依赖。分两部分：
  vendor/  ← 内嵌第三方源码（不可改，CI checksum 校验）
    bitcoin-sha256/   (MIT)    → SHA256/SHA512/HMAC/RIPEMD160/Hash160
    libsodium/        (ISC)    → ChaCha20Poly1305 (ietf)
    bitcoin-muhash/   (MIT)    → MuHash3072（含 3072 位模运算）※ M5 决策点
    siphash/          (MIT)    → SipHash-2-4
  glue/    ← 自研胶水（可改，必须 fuzz + Ditcoin 专属向量）
    dtc_hash.c        → dtc_sha256d / dtc_sha256d_2parts / dtc_tagged_hash("DTC/...")
    dtc_hkdf.c        → HKDF 封装 + Ditcoin salt 拼接
    dtc_sighash.c     → sighash_hash + DTC_SIGHASH_DOMAIN_SEP 开关
    dtc_reader.c      → 带边界检查的 CompactSize/LE 读写
dtc_util      ← crypto    arena/vec/map/log/serialize/thread/file
dtc_consensus ← crypto    params/merkle/amount/pow/lwma/script
dtc_secp      ← 独立      vendored libsecp256k1 (git submodule)
dtc_kernel    ← consensus,crypto,util   blockindex/chainstate/UTXO/validation/snapshot
dtc_policy    ← consensus,util          standardness/topology/package/fees
dtc_mempool   ← policy,kernel(只读)      cluster/linearize/RBF/eviction
dtc_net       ← kernel,mempool,util      transport v1/v2/addrman/peer FSM
dtc_wallet    ← consensus,crypto,util    descriptor/HD/PSBT/coinselect
dtc_iface     ← vtable                   jsonrpc/rest/zmq/ipc
dtc_qt        ← iface                    GUI C++ 薄壳

──── vendor 清单（写入 SPEC，CI 校验）────
| 库              | 版本/tag | 来源 commit | 许可证 | 集成方式            | 启用模块                                              |
| libsecp256k1    | v0.5.0   | xxxx        | MIT    | git submodule       | recovery,ecdh,extrakeys,schnorrsig,ellswift           |
| libsodium       | 1.0.19   | xxxx        | ISC    | git submodule       | chacha20poly1305_ietf                                 |
| bitcoin-sha256  | commit   | xxxx        | MIT    | 复制 + SHA256SUMS   | —                                                     |
| bitcoin-muhash  | commit   | xxxx        | MIT    | 复制 + SHA256SUMS   | —（M5 决策点，见下）                                  |
| siphash         | commit   | xxxx        | MIT    | 复制 + SHA256SUMS   | —                                                     |

CI 规则：
  - git submodule 必须锁定 tag/commit；复制类必须通过 `sha256sum -c SHA256SUMS`
  - 任何对 vendor/ 的 diff 立即 CI 失败（除升级 PR，且升级 PR 必须更新清单与向量）
  - vendor 库自带标准向量在 vendor 目录内独立跑，结果汇总到 CI；胶水层向量单独跑

──── MuHash 决策点（M1 先不做，M5 再定）────
  M1 的 UTXO 哈希先用「按 outpoint 排序后逐条 SHA256 累加」实现（简单、够用、
  非可交换但自洽性测试足够）。M5 快照校验再决定：
    方案 A：vendor bitcoin-muhash（含其 3072 位 num 运算，体积大）
    方案 B：保持排序 SHA256（快照格式里写明算法版本，未来可升级）
  SPEC 中标注该决策点与两种方案的取舍。

════════ M0 密码学（1–2 周）════════
策略：vendor 成熟实现（不改）+ 自研仅做胶水（必须 fuzz）。
SPEC 中列出每个 vendored 库的版本、许可证、来源 commit（可复现构建）。
CI 增加 "vendor 完整性检查"：submodule 锁定 + 复制类 checksum 校验。

★ 仍必须自研的清单（链级隔离与共识所在，不可 vendor）：
  - dtc_subsidy / dtc_supply_at / LWMA-1（共识创新，已有逐段断言）
  - 所有 "DTC/" 前缀 tagged hash 的调用点（域分隔）
  - v2 握手的派生顺序：ecdh_secret → TaggedHash("DTC/ellswift_xonly_ecdh")
    → HKDF-Extract(salt="ditcoin_v2_shared_secret"||MAGIC) → expand 6 个 key
    → FSChaCha20 封包 → 224 包 rekey
  - MAGIC / HRP / salt 的拼接方式
  - M3 短 ID 表（Ditcoin 自行分配，写入 SPEC）
  - coinbase nLockTime 唯一性检查、64 字节交易禁令检查
  - DTC_SIGHASH_DOMAIN_SEP 开关与两种模式的测试向量

★ 胶水层测试（专属向量，必须保留并扩展）：
  - test_sighash_domain_switch：sep=0 → 852c98044fb00507... ; sep=1 → 9822997af65ff519...
  - HD master 专属向量（seed=000102030405060708090a0b0c0d0e0f）：
      key       = dcb95da27e9161f27180d64c7e7e0fb87cf0df1b0c36e5972ab03ab7dd17e5a4
      chaincode = 12b79390482c7a12ecc714cbd1b3067931ab51c697a68284385e12571c931da5
  - v2 派生向量 vec0（见 M3）
  - FSChaCha20 224 包 rekey：fuzz（边界：第 223/224/225 包、长度流 3 字节跨 rekey）

★ tagged hash 一律加 "DTC/" 前缀。
★ 例外：BIP0340/challenge、BIP0340/aux、BIP0340/nonce、MuSig/* 由 libsecp256k1
  硬编码不可改，须在 SPEC 声明 "Schnorr/MuSig 沿用原语域，链级隔离靠 magic/HRP/salt"。

★ 边界明确示例：
  - ChaCha20Poly1305 用 libsodium；FSChaCha20 的 224 包 rekey 逻辑自研，必须 fuzz
  - SHA256/SHA512/HMAC 用 vendored bitcoin-sha256；dtc_sha256d_2parts 与
    "DTC/" tagged hash 拼接自研，必须有向量
  - CompactSize/LE reader/writer 自研，必须有边界 fuzz（溢出、截断、非最小编码）

验收向量：
  - vendor 自带：RFC8439 / BIP340 / BIP32 CKD / BIP39 / bech32m / descriptor checksum /
    SipHash / HKDF（在 vendor 目录跑，CI 汇总）
  - Ditcoin 胶水层：test_sighash_domain_switch / HD master 向量 / FSChaCha20 rekey fuzz

════════ M1 单机链（6–8 周）════════

LWMA-1 参考实现（已实测，直接照写）：
  k = (N+1)*T/2                        // T=600,N=45 → k=13800
  prev = ts[0] - T
  L = 0 ; sumTarget = 0
  for i in 1..N:
      cur = (ts[i] > prev) ? ts[i] : prev+1        // 强制单调
      L += i * min(6*T, cur - prev)                // 单块上限 6T
      prev = cur ; sumTarget += target[i]
  if L < N*k/3: L = N*k/3                        // = 207000
  next_target = L * sumTarget / (k*N*N)
  实测：稳态 1.0010 / 算力×3 → 0.3343 / 算力÷3 → 3.0010 / 乱序 1.0106

验证流水线（严格按序）：
ContextualCheckBlockHeader:
  prev存在 → PoW(hash≤target，经 dtc_pow_algo_t 抽象) → nBits==lwma1_next_target(...)
  → nTime > MTP(prev 11) → nTime ≤ now_local + 1800
  → height%2016==0 且 height>0 : nTime ≥ T_prev − 7200
  → height%2016==2015          : nTime ≥ T_{height−2015}
CheckBlock:
  非空vtx → 首笔且仅首笔coinbase → 逐笔CheckTransaction(stripped_size != 64)
  → weight≤4M → sigops≤80000 → merkle root → witness commitment
ConnectBlock:
  coinbase scriptSig首项==高度(最小编码)
  → coinbase nLockTime==height−1 且 nSequence!=0xffffffff
  → 取prevouts → 成熟度≥100 → 输入≥输出
  → ★total_out ≤ dtc_supply_at(height+1)  （替代 MAX_MONEY 检查）
  → nLockTime/相对锁 → VerifyScript(flags恒定)
  → ★coinbase_out ≤ dtc_subsidy(height) + fees
  → 写undo → 更新UTXO

脚本 flag 恒定启用（无高度分支）：
  P2SH/DERSIG/NULLDUMMY/CLTV/CSV/WITNESS/TAPROOT
  standardness 追加 STRICTENC/MINIMALDATA/CLEANSTACK/MINIMALIF/NULLFAIL/LOW_S/
                    WITNESS_PUBKEYTYPE/CONST_SCRIPTCODE
Taproot：tweak、tapleaf/tapbranch tagged hash(DTC/前缀)、sighash缓存、OP_CHECKSIGADD
★ sighash 缓存是正确性要求：必须提供 precomputed data 与全部 spent outputs。

链状态：最长链 = 累计 chainwork 最大（256位大数），非高度最高。
reorg：undo回滚 → 断开块交易回灌mempool → 剔除失效/违反新锁时间的。

UTXO 哈希（M1 初版）：
  按 outpoint 排序后逐条 SHA256 累加（简单、自洽性测试足够、非可交换）
  格式：txid_le(32) || vout_LE32 || ((height<<1)|coinbase)_LE32
       || amount_LE64 || CompactSize(spk_len) || spk
  ★ M5 快照时再决定是否升级为 MuHash3072（见 MuHash 决策点）

验收：挖200块 → reindex → UTXO哈希一致；违规块库全拒。
★ 新增 test_subsidy_table（7段逐段断言）
★ 新增 test_pre_tail_sum：sum(subsidy(0..2519999)) == 2067187500000000
★ 新增 test_tail_forever：subsidy(1e8) == 50000000
★ 新增 test_supply_closed_form：闭式解与逐块累加在多个高度一致
★ 新增 test_pow_abstraction / test_pow_scratch(sha256d==0)

════════ M2 P2P v1（4–5 周）════════
帧 MAGIC|command(12)|len|checksum(dSHA256前4)
握手 version→verack，夹 wtxidrelay/sendaddrv2/sendcmpct
addrman(new/tried双表+netgroup分桶)；headers-first + minimumChainWork
compact block: shortID = SipHash-2-4，key取自 SHA256(header||nonce) 前两个LE64，
               截断6字节；v2用wtxid；高带宽模式≤3 peer
inv/getdata/tx + feefilter + 孤儿池(wtxid索引)
addrv2 网络ID沿用通用编码(IPv4=1/IPv6=2/TorV3=4/I2P=5)，与链无关
验收：3节点同步同一tip；Bitcoin magic 连接立即断开。

════════ M3 加密传输 v2（2–3 周，可与M2并行）════════
① initiator: ellswift_create() → send(64字节编码 || garbage≤4095)
   responder: 逐字节比对前16字节 == MAGIC||"version\0\0\0\0\0"
              一旦不匹配立即发自己的编码+garbage（不等满64字节！）；全匹配降级v1
   ★防死锁：收到任意非零字节且自己terminator未发完时，必须至少回一字节
② ecdh_secret = TaggedHash("DTC/ellswift_xonly_ecdh",
                  ellswift_first || ellswift_second || ecdh_x32)
   initiator把自己编码放前，responder把对方放前
③ salt = "ditcoin_v2_shared_secret" || MAGIC
   prk = HKDF-Extract(salt, ecdh_secret)
   expand: initiator_L/initiator_P/responder_L/responder_P/
           garbage_terminators(32B→前16init/后16resp)/session_id
   派生后立即 memory_cleanse(secret,prk,okm)
④ packet = FSChaCha20.enc(len_le24) || FSChaCha20Poly1305.enc(header||contents)
   header 1字节 bit7=ignore(decoy)；总开销20字节
   每方向第一个包的 AAD = 自己刚发的 garbage（不含terminator）
⑤ Rekey 每224包：
   AEAD nonce = LE32(counter%224)||LE64(counter/224)
   rekey nonce 前4字节=FFFFFFFF，加密32个零字节取前32作新key
   长度流同keystream供224次3字节，之后取next32字节，block counter归零
⑥ 双方各发 contents 为空的 version 包，收到忽略内容。握手 1.5 RTT
⑦ 短ID表 Ditcoin 自行分配写入 SPEC；1字节ID 与 \0+12字节ASCII 两种编码都必须能接收
⑧ NODE_P2P_V2=(1<<11)；v2被立即断开时重试v1

★ 专属向量 vec0（ecdh_secret = SHA256("dtc-test-0")）：
  ecdh_secret = 7d4dbf016d724a3d7cc5a5c11bb90f020171b6833d47f9cfdd046dbb356532a5
  initiator_P = f718874969ff625f88067f1eaadf11adb4fe68acedd00d293f8c1c57740e90a4
  session_id  = 927e6eec610b4f69b9f78372b0cef5f5559067c5a1ec56ab80b1310fef173d9f
测试顺序：先跑 XElligatorSwift/XSwiftECInv 解码向量 → 再跑上表派生向量 → 最后两节点联调。
验收：两 Ditcoin 节点 session_id 一致；与 Bitcoin 节点握手必失败。

════════ M4 Mempool（6–8 周）════════
cluster_t { txids[n≤64]; total_vsize≤101000; chunks[] }  /* feerate 单调递减 */
linearization: ancestor-sort + 后处理，设迭代上限与 fallback
挖矿取头部chunk，驱逐踢尾部chunk
vsize = max(witness折扣后vsize, sigops_cost × bytes_per_sigop)

RBF 规则（无信号位，创世起 full-RBF）：
  R3 替换绝对费 ≥ 被替换集合总和
  R4 增量费 ≥ 替换体积 × 0.1 dts/vB
  R5 冲突涉及的不同 cluster 数 ≤ 100
  R6 ★在同一 mempool 背景下★ 整体 feerate diagram 严格变好
     before = base ∪ orig ; after = base ∪ repl
     ⚠️ 孤立比较冲突集合会误放行"更高费率但更低绝对费"，务必带背景！

TRUC 式拓扑限制：自动可替换 / 祖先后代必须同类 / 最多1父1子无carve-out /
                 vsize≤10000 / 有未确认祖先时≤1000 / 单笔可低于minrelayfee只要package达标
配套 sibling eviction + package RBF

Package：≤25笔/≤404000weight、拓扑有序、child-with-parents、无内部冲突重复、
         已在池先dedup、★先逐笔单独验证失败的才进package验证★、
         package feerate只算未入池交易、父费率必须低于package费率
P2P层只做 opportunistic 1p1c（孤儿解析触发）+ submitpackage RPC

验收：diagram单调 / 无免费中继 / 驱逐保拓扑 / pinning场景断言 / 随机图fuzz。

════════ M5 快照加速（3 周）════════
双chainstate共享同一BlockManager：
  正常IBD 1个(ibd) → 加载中 2个(ibd) → 校验通过 2个(snapshot优先下载+占大部分cache)
  → 到tip(cache转background) → background到base(比对UTXO哈希) → 重启清理 1个
文件格式 "dtxo\xff" + version + MAGIC + base_blockhash + coins_count + 逐条coin
校验算法：按 MuHash 决策点选定（A: MuHash3072 / B: 排序 SHA256，格式里写算法版本）
目录 chainstate_snapshot/ + base_blockhash 供重启恢复
索引不受益仍从创世顺序建；后台校验链连接的块不发 ZMQ block 通知
RPC loadtxoutset / dumptxoutset [latest|rollback] / getchainstates
★ 基准用自产快照（M1挖出的链 dumptxoutset），不用任何外部链快照。

════════ M6 钱包（6–8 周，可与M2–M5全程并行）════════
descriptor: pk/pkh/wpkh/sh/wsh/combo/multi/sortedmulti/tr/multi_a/sortedmulti_a/
            addr/raw/rawtr + miniscript(wsh/tr内)
KEY: [fingerprint/84'/0xD17C0DE'/0']dtpub.../0/*  ；multipath <0;1> 展开收款/找零
8字符checksum算法可沿用，但★测试向量须用 dtpub 重算★
HD: HMAC-SHA512(key="Ditcoin seed", seed) → master；CKDpriv/CKDpub；hardened 0x80000000
    指纹 = Hash160(pubkey) 前4字节
助记词: PBKDF2-HMAC-SHA512, salt="mnemonic"+passphrase, 2048轮, 64字节
地址: v0→bech32, v1+→bech32m(常量0x2bc830a3), HRP dtc/tdtc
      实测样例 dtc1pqqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s8hfn26
               dtc1qqqqsyqcyq5rqwzqfpg9scrgwpugpzysn4gz7nq
PSBT: magic "dtpb\xff"，六角色，默认v2风格
选币 BnB+SRD+knapsack + 未确认UTXO补费计算；存储 SQLite
验收：两 Ditcoin 钱包交叉签名 PSBT；导入 xpub/bc1 必须报错。

════════ M7 接口（3–4 周）════════
自研HTTP server；cookie + rpcuser/password；rpcallowip白名单
约45方法：getblockchaininfo(含 pow_hash_name/supply/tail_emission 字段)/
  getblock/getblockheader/gettxout/gettxoutsetinfo/
  getchainstates/loadtxoutset/dumptxoutset/getmempoolinfo/getrawmempool/
  testmempoolaccept/submitpackage/getmempoolcluster/getmempoolfeeratediagram/
  getnetworkinfo/getpeerinfo/addnode/createwallet/getnewaddress/listdescriptors/
  importdescriptors/getbalances/sendtoaddress/send/walletcreatefundedpsbt/
  walletprocesspsbt/bumpfee/rescanblockchain/getblocktemplate/submitblock/
  generatetoaddress/estimatesmartfee/validateaddress/getdescriptorinfo/
  deriveaddresses/decodepsbt/combinepsbt/finalizepsbt/createrawtransaction ...
REST(同端口,-rest): /rest/{tx,block,block/notxdetails,blockpart?offset&size,headers,
  blockhashbyheight,blockfilter,blockfilterheaders,spenttxouts,chaininfo.json,
  getutxos/[checkmempool/],mempool/{info,contents}.json}
  不可变响应 public,immutable,max-age=86400；可变与错误 no-store
ZMQ 五topic 三段式 topic|body|LE32seq：hashtx/rawtx/hashblock/rawblock/sequence
  sequence body = hash+C/D 或 txhash+R/A+LE64 mempool seq；hash反转字节序
验收：dtc-cli 全命令回归。

════════ M8 三进程+GUI+kernel（4–5 周）════════
dtc-node / dtc-wallet / dtc-gui，经 <datadir>/node.sock
纯C IPC：UNIX socket + 长度前缀帧 + handle整数表
★同一 client 线程的调用必须落到同一 server 线程★（避免锁问题、支持嵌套回调）
dtcoin -m node|wallet|gui，-ipcbind= / -ipcconnect=
Mining: submitSolution 返回 reason/debug，重复块 reason="duplicate"

libdtckernel.so（有状态库，不透明句柄 + *_create/*_destroy 配对）：
  dtck_context_options_create/set_chainparams/set_notifications/set_validation_interface
  dtck_context_create / dtck_context_interrupt
  dtck_chainstate_manager_options_create(ctx,datadir,blocksdir)
  dtck_chainstate_manager_create/process_block_header/process_block/
                          get_best_entry/import_blocks
  dtck_transaction_check(tx,state)   /* context-free */
  dtck_script_pubkey_verify(spk,amount,tx,precomp,idx,flags,status)
回调两组：notifications(block_tip/header_tip/progress/warning_set/warning_unset/
                        flush_error/fatal_error)
          validation(block_checked/pow_valid_block/block_connected/block_disconnected)
API约定：*_create标warn_unused_result；句柄参数标nonnull；const指针=借用视图不转移所有权；
  传入指针返回后即可释放；数组长度紧跟其指针；
  ★process_block 返回值不代表区块有效性★（走 block_checked 回调）；
  ★日志回调来自任意线程、串行化、不得回调其他API（会死锁）★
Qt 6.8.x C++薄壳仅调 dtc_gui_bridge.h；GUI进程禁止链接kernel
验收：GUI崩溃不影响node；外部程序链接kernel独立验块。

════════ 测试策略（三层，禁止以"与 Bitcoin Core 一致"为验收标准）════════
第1层 算法向量：
  - vendor 自带向量（在 vendor 目录独立跑，CI 汇总）：
      RFC8439 / BIP340 / BIP32 CKD / BIP39 / bech32m / descriptor checksum / SipHash / HKDF
  - Ditcoin 胶水层向量（单独跑，必须可由脚本再生）：
      test_sighash_domain_switch（sep=0/1 两种模式产出不同哈希）
      HD master 专属向量（seed=000102030405060708090a0b0c0d0e0f）
      v2 派生向量 vec0
      FSChaCha20 224 包 rekey 向量 + fuzz（第 223/224/225 包边界）
      "DTC/" tagged hash 向量
  - subsidy 7 段表 + 前 2520000 块累计和
  ★凡改动 salt/标签/版本字节的必须重新生成 Ditcoin 专属向量★
第2层 自洽性：挖N块→dumptxoutset→新节点reindex→UTXO哈希一致；
      双节点独立同步→tip/chainwork/UTXO一致；自产快照加载→后台校验匹配；
      并发出块→reorg后收敛；LWMA稳态/±3×/乱序比值符合预期
      ★长跑模拟：挖到 height=2520000 后继续1000块，断言补贴恒为 0.5 DTC★
      ★供给曲线：任意高度 supply_at(h) 与逐块累加一致★
第3层 对抗与隔离：
  违规块库(全拒)：坏PoW/错nBits/MTP越界/FTL越界/锚点timewarp/负周期时长/
    超额coinbase/coinbase nLockTime错/coinbase nSequence=0xffffffff/64字节交易/
    错merkle/错witness commitment/未成熟coinbase/超weight/超sigops/
    ★total_out > supply_at(h+1)★
  mempool性质：diagram单调/无免费中继/驱逐保拓扑/pinning场景
  ★隔离测试(全拒)★：
    Bitcoin magic f9beb4d9/0b110907/fabfb5da/1c163f28/46495645 → 立即断开
    Bitcoin genesis hash → 拒绝
    bc1/tb1/bcrt1 地址 → 解析报错
    xpub/xprv/tpub/tprv → 导入报错
    Bitcoin PSBT magic 70736274ff → 解析报错
    Bitcoin 快照 magic 7574786fff → 加载报错
    用 bitcoin_v2_shared_secret salt 的握手 → AEAD认证失败
  ★创世唯一性断言：Ditcoin genesis ∉ {BTC main/test/reg/testnet4/testnet5}★
  ★文档完整性 CI：扫描 SPEC/README 必须包含下述三段声明★
  ★vendor 完整性 CI：submodule 锁定 + 复制类 sha256sum -c 通过★
每模块 libFuzzer harness（反序列化/脚本/v2包/cluster线性化/FSChaCha20 rekey/reader边界）

════════ 必须写入 SPEC/README 的三段声明（CI 检查，不可省略）════════

【声明一：跨链重放安全性依赖】
  本链 legacy 与 segwit-v0 sighash 沿用 Bitcoin 原算法，未做域分离
  （DTC_SIGHASH_DOMAIN_SEP 默认为 0）。
  跨链重放安全性【完全依赖创世块唯一性】：
    Ditcoin 创世块 ≠ Bitcoin 创世块 ⇒ 两链 UTXO 集不相交
    ⇒ 不存在相同 (txid, vout) ⇒ 签名无法跨链重放。
  ★ 若将来引入跨链桥、共享测试夹具或任何形式的 UTXO 映射，
    必须先把 DTC_SIGHASH_DOMAIN_SEP 置 1 并重算全部 sighash 向量。
  Taproot 层已通过 TaggedHash("DTC/TapSighash", ...) 天然隔离，不受此影响。

【声明二：算力安全】
  Ditcoin 使用 SHA256d PoW，与 Bitcoin 共用同一算力市场。
  后果：
    - 任何 Bitcoin ASIC 矿池无需改造即可挖 Ditcoin；
    - 持有少量 BTC 算力的攻击者即可对 Ditcoin 发动 51% 攻击；
    - 本链【不提供】抗 ASIC 或算力隔离保证。
  这是为"最小实现"目标做的有意取舍。若将来真实上线，必须评估：
    P1 Scrypt（隔离 BTC 算力，实现简单，LTC/DOGE 路线）
    P4 AuxPOW（主动与 BTC 矿池合并挖矿借算力，DOGE 路线）
    P3 RandomX（抗 ASIC 最强，但需完整 VM，+2~3 个月工作量）
  切换只需替换 dtc_pow_algo_t 实现并重新挖创世块。

【声明三：经济模型差异】
  Bitcoin: 总量硬上限 20,999,999.98，约 2140 年后区块补贴归零，
           矿工收入完全依赖手续费市场。
  Ditcoin: 无硬上限；前 48 年发行 20,671,875 DTC，之后每年固定新增
           26,280 DTC。通胀率单调趋零但永不为零，矿工永远有区块补贴保底。
  ⇒ 这是与 Bitcoin 本质不同的经济模型，而非参数等价变换。

════════ 执行顺序 ════════
params.c → 目录树+CMake+dtc_interfaces.h
→ M0：先 vendor 成熟实现（submodule 锁定 + SHA256SUMS）并跑通 vendor 自带标准向量，
        再写胶水层（dtc_hash/dtc_hkdf/dtc_sighash/dtc_reader）并跑 Ditcoin 专属向量 + fuzz
→ M1 → (M2 ∥ M6) → M3 → M4 → M5 → M7 → M8
★第一步先搭自洽性测试框架★（双节点 + reindex断言 + 违规块库 + 隔离测试 + vendor 完整性检查），
之后每完成一个模块立即跑三层测试并给出对应向量。

════════ 交付物 ════════
DITCOIN-SPEC.md（参数表 + vendor 清单 + 偏离清单 + 冻结向量 + 三段声明 + MuHash 决策点）
CMake工程 + 各模块静态库
dtcoin / dtc-cli / dtc-node / dtc-wallet / dtc-gui
libdtckernel.so + dtckernel.h
三层测试套件 + Ditcoin专属向量生成脚本 + vendor 完整性检查脚本
README（定位澄清 + 独立实验链 + 代币无价值 + 勿转真实资产 + 算力风险 警告）

现在开始：先输出 params.c 完整可编译草案（含 subsidy/supply_at/pow抽象/sighash开关），
再输出目录树 + CMakeLists 骨架 + dtc_interfaces.h + vendor 清单，
然后从 M0 crypto 开始：先 vendor 成熟实现并跑通标准向量，再写胶水层并跑 Ditcoin 专属向量与 fuzz。