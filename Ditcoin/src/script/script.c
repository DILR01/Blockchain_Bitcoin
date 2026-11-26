/*
 * script.c —— 脚本解析与 legacy 解释器（含 P2SH）
 *
 * 说明（与 SPEC 的差距必须显式记录，绝不假装支持）：
 *   * 本实现执行 legacy 脚本与 P2SH；witness program（v0/v1）会被明确
 *     拒绝并返回错误，而不是按 legacy 语义误判为真。
 *   * 签名验证通过 vtable 注入，引擎本身不含密码学实现。
 *   * flag 恒定启用：P2SH/DERSIG/NULLDUMMY/CLTV/CSV；witness/taproot 仅
 *     用于识别并拒绝。
 */
#include "dtc/script.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtc/crypto.h"

/* ---- 解释器状态 ---- */

typedef struct {
    uint8_t data[DTC_MAX_ELEMENT_SIZE];
    size_t len;
} stack_item;

#define DTC_MAX_COND_DEPTH 64

typedef struct {
    stack_item *stack;
    size_t sp;
    stack_item *altstack;
    size_t alt_sp;
    bool vf_exec[DTC_MAX_COND_DEPTH];
    size_t exec_depth;
    size_t op_count;

    const dtc_script_ctx *ctx;
    const dtc_tx *tx;
    size_t input_index;
    dtc_amount amount;

    /*
     * 当前正在执行的脚本（legacy 下 scriptSig、scriptPubKey、redeem 分开执行，
     * 每次执行前由 eval_script 设置），以及最后一个已执行 OP_CODESEPARATOR
     * 之后的位置 —— 二者共同决定 CHECKSIG 使用的 scriptCode。
     */
    const uint8_t *cur_script;
    size_t cur_len;
    size_t codesep_pos;

    char *err;
    size_t errcap;
} interp;

static void set_error(interp *it, const char *msg)
{
    if (it->err != NULL && it->errcap > 0 && it->err[0] == '\0') {
        (void)snprintf(it->err, it->errcap, "%s", msg);
    }
}

static bool all_exec(const interp *it)
{
    for (size_t i = 0; i < it->exec_depth; ++i) {
        if (!it->vf_exec[i]) {
            return false;
        }
    }
    return true;
}

static bool push_item(interp *it, const uint8_t *data, size_t len)
{
    /* Bitcoin 规则：stack 与 altstack 合计条目数不得超过 1000 */
    if (it->sp + it->alt_sp >= DTC_MAX_STACK_SIZE) {
        set_error(it, "栈溢出");
        return false;
    }
    if (len > DTC_MAX_ELEMENT_SIZE) {
        set_error(it, "元素超过 520 字节");
        return false;
    }
    stack_item *v = &it->stack[it->sp++];
    v->len = len;
    if (len > 0) {
        memcpy(v->data, data, len);
    }
    return true;
}

static bool pop_item(interp *it, stack_item **out)
{
    if (it->sp == 0) {
        set_error(it, "栈下溢");
        return false;
    }
    --it->sp;
    *out = &it->stack[it->sp];
    return true;
}

static bool top_item(interp *it, stack_item **out)
{
    if (it->sp == 0) {
        set_error(it, "栈下溢");
        return false;
    }
    *out = &it->stack[it->sp - 1];
    return true;
}

/* 脚本布尔语义：负零（0x80）与全零为 false */
static bool cast_bool(const stack_item *v)
{
    for (size_t i = 0; i < v->len; ++i) {
        if (v->data[i] != 0) {
            if (i == v->len - 1 && v->data[i] == 0x80) {
                return false;
            }
            return true;
        }
    }
    return false;
}

/*
 * 解析脚本数字（CScriptNum 语义）：
 *   * 最多 4 字节（脚本内数字），符号-数值小端，最高位为符号位；
 *   * 必须是最小编码，否则视为非法（Bitcoin 从 BIP62 起强制）；
 *   * 因此「0x80 表示负零」这类非最小形式会被拒绝。
 */
static bool decode_num(const stack_item *v, int64_t *out)
{
    if (v->len > DTC_MAX_SCRIPT_NUM_LEN) {
        return false;
    }
    if (v->len == 0) {
        *out = 0;
        return true;
    }
    /* 最小编码检查：末尾字节除符号位外为 0 时，不允许冗余 0x00/0x80 */
    if ((v->data[v->len - 1] & 0x7fu) == 0 &&
        (v->len == 1 || (v->data[v->len - 2] & 0x80u) == 0)) {
        return false;
    }

    uint32_t raw = 0;
    for (size_t i = 0; i < v->len; ++i) {
        raw |= (uint32_t)v->data[i] << (8 * i);
    }
    if ((v->data[v->len - 1] & 0x80u) != 0) {
        raw &= ~(0x80u << (8 * (v->len - 1)));
        *out = -(int64_t)raw;
    } else {
        *out = (int64_t)raw;
    }
    return true;
}

static bool push_num(interp *it, int64_t value)
{
    uint8_t tmp[8];
    size_t n = 0;
    bool neg = value < 0;
    /* 用 -(value+1)+1 避免对 INT64_MIN 取负导致的有符号溢出（UB） */
    uint64_t abs = neg ? (uint64_t)(-(value + 1)) + 1u : (uint64_t)value;

    while (abs > 0) {
        tmp[n++] = (uint8_t)(abs & 0xffu);
        abs >>= 8;
    }
    if (n == 0) {
        tmp[n++] = 0;
    } else if ((tmp[n - 1] & 0x80u) != 0) {
        tmp[n++] = 0;
    }
    if (neg) {
        tmp[n - 1] |= 0x80u;
    }
    return push_item(it, tmp, n);
}

static bool push_bool(interp *it, bool value)
{
    uint8_t v = value ? 1 : 0;
    return push_item(it, &v, 1);
}

/* 解析数字并压入结果（二元运算辅助） */
static bool binary_numeric(interp *it, int64_t (*fn)(int64_t, int64_t))
{
    stack_item *b;
    stack_item *a;
    if (!pop_item(it, &b) || !pop_item(it, &a)) {
        return false;
    }
    int64_t va;
    int64_t vb;
    if (!decode_num(a, &va) || !decode_num(b, &vb)) {
        set_error(it, "数字编码非法");
        return false;
    }
    return push_num(it, fn(va, vb));
}

static bool unary_numeric(interp *it, int64_t (*fn)(int64_t))
{
    stack_item *a;
    if (!pop_item(it, &a)) {
        return false;
    }
    int64_t va;
    if (!decode_num(a, &va)) {
        set_error(it, "数字编码非法");
        return false;
    }
    return push_num(it, fn(va));
}

/* ---- 算术函数 ---- */
static int64_t op_add(int64_t a, int64_t b) { return a + b; }
static int64_t op_sub(int64_t a, int64_t b) { return a - b; }
static int64_t op_min(int64_t a, int64_t b) { return a < b ? a : b; }
static int64_t op_max(int64_t a, int64_t b) { return a > b ? a : b; }
static int64_t op_negate(int64_t a) { return -a; }
static int64_t op_abs(int64_t a) { return a < 0 ? -a : a; }
static int64_t op_not(int64_t a) { return a == 0 ? 1 : 0; }
static int64_t op_zero_not_equal(int64_t a) { return a != 0 ? 1 : 0; }
static int64_t op_inc(int64_t a) { return a + 1; }
static int64_t op_dec(int64_t a) { return a - 1; }

/*
 * 比较类二元运算：kind 0=EQ 1=NE 2=LT 3=GT 4=LE 5=GE
 * 结果通过 *out 返回，便于 NUMEQUAL / NUMEQUALVERIFY 复用。
 */
static bool compare_numeric(interp *it, int kind, bool *out)
{
    stack_item *b;
    stack_item *a;
    if (!pop_item(it, &b) || !pop_item(it, &a)) {
        return false;
    }
    int64_t va;
    int64_t vb;
    if (!decode_num(a, &va) || !decode_num(b, &vb)) {
        set_error(it, "数字编码非法");
        return false;
    }
    switch (kind) {
    case 0: *out = (va == vb); break;
    case 1: *out = (va != vb); break;
    case 2: *out = (va < vb); break;
    case 3: *out = (va > vb); break;
    case 4: *out = (va <= vb); break;
    default: *out = (va >= vb); break;
    }
    return true;
}

/* ---- 脚本解析 ---- */

/* 取得一个 push 的数据（调用方保证 op 是 push 类） */
static bool read_push(const uint8_t *script, size_t len, size_t *pos, uint8_t op,
                      const uint8_t **data, size_t *datalen)
{
    size_t n = 0;
    if (op <= 0x4b) {
        n = op;
    } else if (op == 0x4c) {
        if (*pos + 1 > len) {
            return false;
        }
        n = script[*pos];
        *pos += 1;
    } else if (op == 0x4d) {
        if (*pos + 2 > len) {
            return false;
        }
        n = (size_t)script[*pos] | ((size_t)script[*pos + 1] << 8);
        *pos += 2;
    } else if (op == 0x4e) {
        if (*pos + 4 > len) {
            return false;
        }
        n = (size_t)script[*pos] | ((size_t)script[*pos + 1] << 8) |
            ((size_t)script[*pos + 2] << 16) |
            ((size_t)script[*pos + 3] << 24);
        *pos += 4;
    } else {
        return false;
    }

    if (n > len - *pos) {
        return false;
    }
    *data = script + *pos;
    *datalen = n;
    *pos += n;
    return true;
}

/*
 * 取出当前 CHECKSIG 应使用的 scriptCode：
 * 即「当前脚本中最后一个已执行 OP_CODESEPARATOR 之后」的部分。
 */
static const uint8_t *current_script_code(const interp *it, size_t *len_out)
{
    *len_out = it->cur_len - it->codesep_pos;
    return it->cur_script + it->codesep_pos;
}

/*
 * Bitcoin legacy 的 FindAndDelete(sig) 语义：
 * 从 script 中删除所有「恰好等于该签名 push 序列」的片段（只在操作码边界匹配）。
 * 这意味着 scriptCode ≤ 10000 字节，输出缓冲区由调用方提供。
 * 返回写入 out 的字节数。
 */
static size_t find_and_delete(const uint8_t *script, size_t len,
                              const uint8_t *sig, size_t siglen, uint8_t *out)
{
    uint8_t pat[1 + DTC_MAX_ELEMENT_SIZE];
    size_t patlen;

    /* 只有 1..75 字节的签名才用直接 push 编码；其余情况不删除，原样输出 */
    if (siglen == 0 || siglen > 75) {
        if (len > 0) {
            memcpy(out, script, len);
        }
        return len;
    }
    pat[0] = (uint8_t)siglen;
    memcpy(pat + 1, sig, siglen);
    patlen = siglen + 1;

    size_t i = 0;
    size_t o = 0;
    while (i < len) {
        /* 仅在操作码边界上匹配 */
        if (len - i >= patlen && memcmp(script + i, pat, patlen) == 0) {
            i += patlen;
            continue;
        }
        size_t start = i;
        uint8_t op = script[i++];
        size_t datalen = 0;
        if (op <= 0x4b) {
            datalen = op;
        } else if (op == 0x4c) {
            if (i + 1 > len) {
                memcpy(out + o, script + start, len - start);
                o += len - start;
                break;
            }
            datalen = script[i];
            i += 1;
        } else if (op == 0x4d) {
            if (i + 2 > len) {
                memcpy(out + o, script + start, len - start);
                o += len - start;
                break;
            }
            datalen = (size_t)script[i] | ((size_t)script[i + 1] << 8);
            i += 2;
        } else if (op == 0x4e) {
            if (i + 4 > len) {
                memcpy(out + o, script + start, len - start);
                o += len - start;
                break;
            }
            datalen = (size_t)script[i] | ((size_t)script[i + 1] << 8) |
                      ((size_t)script[i + 2] << 16) |
                      ((size_t)script[i + 3] << 24);
            i += 4;
        }
        if (datalen > len - i) {
            /* 截断的 push：剩余字节原样拷贝（脚本本身会在解释阶段报错） */
            memcpy(out + o, script + start, len - start);
            o += len - start;
            break;
        }
        i += datalen;
        memcpy(out + o, script + start, i - start);
        o += i - start;
    }
    return o;
}

/*
 * 校验单个签名（CHECKSIG / CHECKMULTISIG 共用）。
 * 负责：取 scriptCode → FindAndDelete 自身 → 计算 legacy sighash → 回调验签。
 * 任何一步失败都返回 false（脚本层据此压入 false 或直接失败）。
 */
static bool check_one_sig(interp *it, const uint8_t *sig, size_t siglen,
                          const uint8_t *pubkey, size_t pubkeylen)
{
    if (siglen == 0 || it->ctx == NULL || it->ctx->checker == NULL ||
        it->ctx->checker->check_ecdsa == NULL || it->tx == NULL) {
        return false;
    }
    size_t codelen = 0;
    const uint8_t *code = current_script_code(it, &codelen);

    uint8_t filtered[DTC_MAX_SCRIPT_SIZE];
    codelen = find_and_delete(code, codelen, sig, siglen, filtered);

    uint32_t hashtype = sig[siglen - 1];
    uint8_t hash[32];
    if (!dtc_sighash_legacy(it->tx, it->input_index, filtered, codelen, hashtype,
                            hash)) {
        return false;
    }
    return it->ctx->checker->check_ecdsa(it->ctx->checker->ctx, sig, siglen - 1,
                                         pubkey, pubkeylen, hash);
}

/* CHECKSIG / CHECKSIGVERIFY */
static bool op_checksig(interp *it, bool verify)
{
    stack_item *sig;
    stack_item *pub;
    /* 栈顶是公钥，其下是签名（与 Bitcoin 的 <pubkey> OP_CHECKSIG 一致） */
    if (it->sp < 2 || !top_item(it, &pub)) {
        set_error(it, "CHECKSIG 缺少参数");
        return false;
    }
    sig = &it->stack[it->sp - 2];
    it->sp -= 2;

    bool ok = check_one_sig(it, sig->data, sig->len, pub->data, pub->len);

    if (verify) {
        if (!ok) {
            set_error(it, "CHECKSIGVERIFY 失败");
            return false;
        }
        return true;
    }
    return push_bool(it, ok);
}

/* CHECKMULTISIG / CHECKMULTISIGVERIFY */
static bool op_checkmultisig(interp *it, bool verify)
{
    stack_item *nitem;
    if (!pop_item(it, &nitem)) {
        return false;
    }
    int64_t nkeys;
    if (!decode_num(nitem, &nkeys) || nkeys < 0 ||
        nkeys > DTC_MAX_PUBKEYS_PER_MULTISIG) {
        set_error(it, "CHECKMULTISIG 公钥数量非法");
        return false;
    }
    if (it->sp < (size_t)nkeys + 1) {
        set_error(it, "CHECKMULTISIG 栈不足");
        return false;
    }

    stack_item *keys[DTC_MAX_PUBKEYS_PER_MULTISIG];
    for (int64_t i = nkeys - 1; i >= 0; --i) {
        keys[i] = &it->stack[it->sp - 1];
        --it->sp;
    }

    stack_item *mitem;
    if (!pop_item(it, &mitem)) {
        return false;
    }
    int64_t nsigs;
    if (!decode_num(mitem, &nsigs) || nsigs < 0 || nsigs > nkeys) {
        set_error(it, "CHECKMULTISIG 签名数量非法");
        return false;
    }
    if (it->sp < (size_t)nsigs + 1) {
        set_error(it, "CHECKMULTISIG 栈不足");
        return false;
    }

    stack_item *sigs[DTC_MAX_PUBKEYS_PER_MULTISIG];
    for (int64_t i = nsigs - 1; i >= 0; --i) {
        sigs[i] = &it->stack[it->sp - 1];
        --it->sp;
    }

    stack_item *dummy;
    if (!pop_item(it, &dummy)) {
        return false;
    }
    if (dummy->len != 0) {
        set_error(it, "CHECKMULTISIG dummy 必须为空（NULLDUMMY）");
        return false;
    }

    bool ok = (it->ctx != NULL && it->ctx->checker != NULL &&
               it->ctx->checker->check_ecdsa != NULL);

    int64_t sig_index = 0;
    int64_t key_index = 0;
    while (ok && sig_index < nsigs && key_index < nkeys) {
        stack_item *sig = sigs[sig_index];
        stack_item *key = keys[key_index];
        bool matched = check_one_sig(it, sig->data, sig->len, key->data,
                                     key->len);
        if (matched) {
            sig_index += 1;
        }
        key_index += 1;
        if (nsigs - sig_index > nkeys - key_index) {
            ok = false; /* 剩余签名多于剩余公钥，必然失败 */
        }
    }
    ok = ok && (sig_index == nsigs);

    if (verify) {
        if (!ok) {
            set_error(it, "CHECKMULTISIGVERIFY 失败");
            return false;
        }
        return true;
    }
    return push_bool(it, ok);
}

/* CLTV：CHECKLOCKTIMEVERIFY */
static bool op_checklocktime(interp *it)
{
    stack_item *item;
    /* CLTV 不消费参数：脚本必须显式 OP_DROP（Bitcoin 语义） */
    if (!top_item(it, &item)) {
        return false;
    }
    int64_t lock;
    if (!decode_num(item, &lock) || lock < 0) {
        set_error(it, "CLTV 参数非法");
        return false;
    }
    if (it->ctx == NULL) {
        set_error(it, "CLTV 缺少上下文");
        return false;
    }
    if (it->ctx->input_sequence == 0xffffffffu) {
        set_error(it, "CLTV 输入为 final");
        return false;
    }
    int64_t tx_lock = it->ctx->tx_locktime;
    /* 高度（< 500000000）与时间戳必须同类型比较 */
    if ((lock < 500000000) != (tx_lock < 500000000)) {
        set_error(it, "CLTV 锁类型不匹配");
        return false;
    }
    if (lock > tx_lock) {
        set_error(it, "CLTV 未满足");
        return false;
    }
    if (lock < 500000000 && lock > it->ctx->block_height) {
        set_error(it, "CLTV 超过当前高度");
        return false;
    }
    return true;
}

/* CSV：CHECKSEQUENCEVERIFY */
static bool op_checksequence(interp *it)
{
    stack_item *item;
    /* CSV 同样不消费参数：脚本必须显式 OP_DROP */
    if (!top_item(it, &item)) {
        return false;
    }
    int64_t seq;
    if (!decode_num(item, &seq) || seq < 0) {
        set_error(it, "CSV 参数非法");
        return false;
    }
    if (it->ctx == NULL) {
        set_error(it, "CSV 缺少上下文");
        return false;
    }
    /* 第 31 位为 disable 标志：直接放行 */
    if ((seq & (1LL << 31)) != 0) {
        return true;
    }
    uint32_t txseq = it->ctx->input_sequence;
    if ((txseq & 0x80000000u) != 0) {
        set_error(it, "CSV 输入 sequence 已禁用");
        return false;
    }
    bool want_time = (seq & (1LL << 22)) != 0;
    bool have_time = (txseq & (1u << 22)) != 0;
    if (want_time != have_time) {
        set_error(it, "CSV 类型不匹配");
        return false;
    }
    int64_t mask = (1LL << 22) - 1;
    if ((int64_t)(txseq & 0x003fffffu) < (seq & mask)) {
        set_error(it, "CSV 未满足");
        return false;
    }
    return true;
}

/* 执行一段脚本 */
static bool eval_script(interp *it, const uint8_t *script, size_t len)
{
    if (len > DTC_MAX_SCRIPT_SIZE) {
        set_error(it, "脚本超过 10000 字节");
        return false;
    }

    /* 记录当前脚本，供 CHECKSIG 计算 scriptCode（含 OP_CODESEPARATOR 语义） */
    it->cur_script = script;
    it->cur_len = len;
    it->codesep_pos = 0;
    it->exec_depth = 0;

    size_t pos = 0;
    while (pos < len) {
        uint8_t op = script[pos++];
        bool exec = all_exec(it);

        /* push 类操作：即使不执行也必须正确跳过数据 */
        const uint8_t *push = NULL;
        size_t pushlen = 0;
        bool is_push = (op <= 0x4b) || op == 0x4c || op == 0x4d || op == 0x4e;
        if (is_push) {
            if (!read_push(script, len, &pos, op, &push, &pushlen)) {
                set_error(it, "push 数据截断");
                return false;
            }
            if (!exec) {
                continue;
            }
            if (pushlen > DTC_MAX_ELEMENT_SIZE) {
                set_error(it, "push 元素超过 520 字节");
                return false;
            }
            if (!push_item(it, push, pushlen)) {
                return false;
            }
            continue;
        }

        /* 条件控制指令无论是否执行都要维护状态 */
        if (op == 0x63 || op == 0x64) { /* IF / NOTIF */
            bool value = false;
            if (exec) {
                stack_item *item;
                if (!pop_item(it, &item)) {
                    return false;
                }
                value = cast_bool(item);
                if (op == 0x64) {
                    value = !value;
                }
            }
            if (it->exec_depth >= DTC_MAX_COND_DEPTH) {
                set_error(it, "条件嵌套过深");
                return false;
            }
            it->vf_exec[it->exec_depth++] = exec && value;
            continue;
        }
        if (op == 0x67) { /* ELSE */
            if (it->exec_depth == 0) {
                set_error(it, "ELSE 缺少 IF");
                return false;
            }
            it->vf_exec[it->exec_depth - 1] = !it->vf_exec[it->exec_depth - 1];
            continue;
        }
        if (op == 0x68) { /* ENDIF */
            if (it->exec_depth == 0) {
                set_error(it, "ENDIF 缺少 IF");
                return false;
            }
            --it->exec_depth;
            continue;
        }

        if (!exec) {
            continue;
        }

        /* 与 Bitcoin 一致：只对 op > OP_16 的操作码计数（push 不受 201 限制） */
        if (op > 0x60) {
            it->op_count += 1;
            if (it->op_count > DTC_MAX_OPS_PER_SCRIPT) {
                set_error(it, "操作码数量超过 201");
                return false;
            }
        }

        switch (op) {
        case 0x4f: /* OP_1NEGATE */
            if (!push_num(it, -1)) {
                return false;
            }
            break;
        case 0x51: /* OP_1 */
        case 0x52:
        case 0x53:
        case 0x54:
        case 0x55:
        case 0x56:
        case 0x57:
        case 0x58:
        case 0x59:
        case 0x5a:
        case 0x5b:
        case 0x5c:
        case 0x5d:
        case 0x5e:
        case 0x5f:
        case 0x60: /* OP_16 */
            if (!push_num(it, (int64_t)op - 0x50)) {
                return false;
            }
            break;
        case 0x61:   /* NOP */
        case 0xb0:   /* NOP1 */
        case 0xb3:   /* NOP4 */
        case 0xb4:   /* NOP5 */
        case 0xb5:   /* NOP6 */
        case 0xb6:   /* NOP7 */
        case 0xb7:   /* NOP8 */
        case 0xb8:   /* NOP9 */
        case 0xb9:   /* NOP10 */
            /* 预留 NOP：与 Bitcoin 一致，执行时无副作用 */
            break;
        case 0x69: { /* VERIFY */
            stack_item *item;
            if (!pop_item(it, &item)) {
                return false;
            }
            if (!cast_bool(item)) {
                set_error(it, "VERIFY 失败");
                return false;
            }
            break;
        }
        case 0x6a: /* RETURN */
            set_error(it, "OP_RETURN");
            return false;
        case 0x6b: { /* TOALTSTACK */
            stack_item *item;
            if (!pop_item(it, &item)) {
                return false;
            }
            if (it->alt_sp >= DTC_MAX_STACK_SIZE) {
                set_error(it, "altstack 溢出");
                return false;
            }
            it->altstack[it->alt_sp++] = *item;
            break;
        }
        case 0x6c: { /* FROMALTSTACK */
            if (it->alt_sp == 0) {
                set_error(it, "altstack 下溢");
                return false;
            }
            --it->alt_sp;
            if (!push_item(it, it->altstack[it->alt_sp].data,
                           it->altstack[it->alt_sp].len)) {
                return false;
            }
            break;
        }
        case 0x6d: { /* 2DROP */
            stack_item *a;
            stack_item *b;
            if (!pop_item(it, &a) || !pop_item(it, &b)) {
                return false;
            }
            break;
        }
        case 0x6e: { /* 2DUP */
            if (it->sp < 2) {
                set_error(it, "2DUP 栈不足");
                return false;
            }
            stack_item a = it->stack[it->sp - 2];
            stack_item b = it->stack[it->sp - 1];
            if (!push_item(it, a.data, a.len) || !push_item(it, b.data, b.len)) {
                return false;
            }
            break;
        }
        case 0x6f: { /* 3DUP */
            if (it->sp < 3) {
                set_error(it, "3DUP 栈不足");
                return false;
            }
            stack_item a = it->stack[it->sp - 3];
            stack_item b = it->stack[it->sp - 2];
            stack_item c = it->stack[it->sp - 1];
            if (!push_item(it, a.data, a.len) || !push_item(it, b.data, b.len) ||
                !push_item(it, c.data, c.len)) {
                return false;
            }
            break;
        }
        case 0x70: { /* 2OVER */
            if (it->sp < 4) {
                set_error(it, "2OVER 栈不足");
                return false;
            }
            stack_item a = it->stack[it->sp - 4];
            stack_item b = it->stack[it->sp - 3];
            if (!push_item(it, a.data, a.len) || !push_item(it, b.data, b.len)) {
                return false;
            }
            break;
        }
        case 0x72: { /* 2SWAP */
            if (it->sp < 4) {
                set_error(it, "2SWAP 栈不足");
                return false;
            }
            stack_item a = it->stack[it->sp - 4];
            stack_item b = it->stack[it->sp - 3];
            it->stack[it->sp - 4] = it->stack[it->sp - 2];
            it->stack[it->sp - 3] = it->stack[it->sp - 1];
            it->stack[it->sp - 2] = a;
            it->stack[it->sp - 1] = b;
            break;
        }
        case 0x73: { /* IFDUP */
            stack_item *item;
            if (!top_item(it, &item)) {
                return false;
            }
            if (cast_bool(item)) {
                if (!push_item(it, item->data, item->len)) {
                    return false;
                }
            }
            break;
        }
        case 0x74: { /* DEPTH */
            if (!push_num(it, (int64_t)it->sp)) {
                return false;
            }
            break;
        }
        case 0x75: { /* DROP */
            stack_item *item;
            if (!pop_item(it, &item)) {
                return false;
            }
            break;
        }
        case 0x76: { /* DUP */
            stack_item *item;
            if (!top_item(it, &item)) {
                return false;
            }
            if (!push_item(it, item->data, item->len)) {
                return false;
            }
            break;
        }
        case 0x77: { /* NIP */
            stack_item *a;
            stack_item *b;
            if (!pop_item(it, &a) || !pop_item(it, &b)) {
                return false;
            }
            if (!push_item(it, a->data, a->len)) {
                return false;
            }
            break;
        }
        case 0x78: { /* OVER */
            if (it->sp < 2) {
                set_error(it, "OVER 栈不足");
                return false;
            }
            stack_item *item = &it->stack[it->sp - 2];
            if (!push_item(it, item->data, item->len)) {
                return false;
            }
            break;
        }
        case 0x79: { /* PICK */
            stack_item *n;
            if (!pop_item(it, &n)) {
                return false;
            }
            int64_t depth;
            if (!decode_num(n, &depth) || depth < 0 ||
                (size_t)depth >= it->sp) {
                set_error(it, "PICK 参数非法");
                return false;
            }
            stack_item *item = &it->stack[it->sp - 1 - (size_t)depth];
            if (!push_item(it, item->data, item->len)) {
                return false;
            }
            break;
        }
        case 0x7a: { /* ROLL */
            stack_item *n;
            if (!pop_item(it, &n)) {
                return false;
            }
            int64_t depth;
            if (!decode_num(n, &depth) || depth < 0 ||
                (size_t)depth >= it->sp) {
                set_error(it, "ROLL 参数非法");
                return false;
            }
            size_t index = it->sp - 1 - (size_t)depth;
            stack_item tmp = it->stack[index];
            memmove(&it->stack[index], &it->stack[index + 1],
                    (it->sp - index - 1) * sizeof(stack_item));
            it->stack[it->sp - 1] = tmp;
            break;
        }
        case 0x7b: { /* ROT */
            if (it->sp < 3) {
                set_error(it, "ROT 栈不足");
                return false;
            }
            stack_item tmp = it->stack[it->sp - 3];
            it->stack[it->sp - 3] = it->stack[it->sp - 2];
            it->stack[it->sp - 2] = it->stack[it->sp - 1];
            it->stack[it->sp - 1] = tmp;
            break;
        }
        case 0x7c: { /* SWAP */
            if (it->sp < 2) {
                set_error(it, "SWAP 栈不足");
                return false;
            }
            stack_item tmp = it->stack[it->sp - 1];
            it->stack[it->sp - 1] = it->stack[it->sp - 2];
            it->stack[it->sp - 2] = tmp;
            break;
        }
        case 0x7d: { /* TUCK */
            if (it->sp < 2) {
                set_error(it, "TUCK 栈不足");
                return false;
            }
            stack_item a = it->stack[it->sp - 2];
            stack_item b = it->stack[it->sp - 1];
            it->stack[it->sp - 2] = b;
            it->stack[it->sp - 1] = a;
            if (!push_item(it, b.data, b.len)) {
                return false;
            }
            break;
        }
        case 0x82: { /* SIZE */
            stack_item *item;
            if (!pop_item(it, &item)) {
                return false;
            }
            if (!push_num(it, (int64_t)item->len)) {
                return false;
            }
            break;
        }
        case 0x87:   /* EQUAL */
        case 0x88: { /* EQUALVERIFY */
            stack_item *a;
            stack_item *b;
            if (!pop_item(it, &b) || !pop_item(it, &a)) {
                return false;
            }
            bool eq = (a->len == b->len) &&
                      (a->len == 0 || memcmp(a->data, b->data, a->len) == 0);
            if (op == 0x88) {
                if (!eq) {
                    set_error(it, "EQUALVERIFY 失败");
                    return false;
                }
            } else if (!push_bool(it, eq)) {
                return false;
            }
            break;
        }
        case 0x8b: /* 1ADD */
            if (!unary_numeric(it, op_inc)) {
                return false;
            }
            break;
        case 0x8c: /* 1SUB */
            if (!unary_numeric(it, op_dec)) {
                return false;
            }
            break;
        case 0x8f: /* NEGATE */
            if (!unary_numeric(it, op_negate)) {
                return false;
            }
            break;
        case 0x90: /* ABS */
            if (!unary_numeric(it, op_abs)) {
                return false;
            }
            break;
        case 0x91: /* NOT */
            if (!unary_numeric(it, op_not)) {
                return false;
            }
            break;
        case 0x92: /* 0NOTEQUAL */
            if (!unary_numeric(it, op_zero_not_equal)) {
                return false;
            }
            break;
        case 0x93: /* ADD */
            if (!binary_numeric(it, op_add)) {
                return false;
            }
            break;
        case 0x94: /* SUB */
            if (!binary_numeric(it, op_sub)) {
                return false;
            }
            break;
        case 0x9a:   /* BOOLAND */
        case 0x9b: { /* BOOLOR */
            stack_item *a;
            stack_item *b;
            if (!pop_item(it, &b) || !pop_item(it, &a)) {
                return false;
            }
            bool va = cast_bool(a);
            bool vb = cast_bool(b);
            bool r = (op == 0x9a) ? (va && vb) : (va || vb);
            if (!push_bool(it, r)) {
                return false;
            }
            break;
        }
        case 0x9c:   /* NUMEQUAL */
        case 0x9d: { /* NUMEQUALVERIFY */
            bool r;
            if (!compare_numeric(it, 0, &r)) {
                return false;
            }
            if (op == 0x9d) {
                /* VERIFY 变体：不相等则整段脚本失败，且不压入结果 */
                if (!r) {
                    set_error(it, "NUMEQUALVERIFY 失败");
                    return false;
                }
            } else if (!push_bool(it, r)) {
                return false;
            }
            break;
        }
        case 0x9e: { /* NUMNOTEQUAL */
            bool r;
            if (!compare_numeric(it, 1, &r) || !push_bool(it, r)) {
                return false;
            }
            break;
        }
        case 0x9f: { /* LESSTHAN */
            bool r;
            if (!compare_numeric(it, 2, &r) || !push_bool(it, r)) {
                return false;
            }
            break;
        }
        case 0xa0: { /* GREATERTHAN */
            bool r;
            if (!compare_numeric(it, 3, &r) || !push_bool(it, r)) {
                return false;
            }
            break;
        }
        case 0xa1: { /* LESSTHANOREQUAL */
            bool r;
            if (!compare_numeric(it, 4, &r) || !push_bool(it, r)) {
                return false;
            }
            break;
        }
        case 0xa2: { /* GREATERTHANOREQUAL */
            bool r;
            if (!compare_numeric(it, 5, &r) || !push_bool(it, r)) {
                return false;
            }
            break;
        }
        case 0xa3: /* MIN */
            if (!binary_numeric(it, op_min)) {
                return false;
            }
            break;
        case 0xa4: /* MAX */
            if (!binary_numeric(it, op_max)) {
                return false;
            }
            break;
        case 0xa5: { /* WITHIN */
            stack_item *max;
            stack_item *min;
            stack_item *x;
            if (!pop_item(it, &max) || !pop_item(it, &min) ||
                !pop_item(it, &x)) {
                return false;
            }
            int64_t vx;
            int64_t vmin;
            int64_t vmax;
            if (!decode_num(x, &vx) || !decode_num(min, &vmin) ||
                !decode_num(max, &vmax)) {
                set_error(it, "WITHIN 参数非法");
                return false;
            }
            if (!push_bool(it, vx >= vmin && vx < vmax)) {
                return false;
            }
            break;
        }
        case 0xa6:   /* RIPEMD160 */
        case 0xa7:   /* SHA1 */
        case 0xa8:   /* SHA256 */
        case 0xa9:   /* HASH160 */
        case 0xaa: { /* HASH256 */
            stack_item *item;
            if (!pop_item(it, &item)) {
                return false;
            }
            uint8_t out[32];
            size_t outlen = 32;
            if (op == 0xa6) {
                dtc_ripemd160(item->data, item->len, out);
                outlen = 20;
            } else if (op == 0xa7) {
                dtc_sha1(item->data, item->len, out);
                outlen = 20;
            } else if (op == 0xa8) {
                dtc_sha256(item->data, item->len, out);
            } else if (op == 0xa9) {
                dtc_hash160(item->data, item->len, out);
                outlen = 20;
            } else {
                dtc_sha256d(item->data, item->len, out);
            }
            if (!push_item(it, out, outlen)) {
                return false;
            }
            break;
        }
        case 0xab: /* OP_CODESEPARATOR：后续 CHECKSIG 的 scriptCode 从此处开始 */
            it->codesep_pos = pos;
            break;
        case 0xac: /* CHECKSIG */
            if (!op_checksig(it, false)) {
                return false;
            }
            break;
        case 0xad: /* CHECKSIGVERIFY */
            if (!op_checksig(it, true)) {
                return false;
            }
            break;
        case 0xae: /* CHECKMULTISIG */
            if (!op_checkmultisig(it, false)) {
                return false;
            }
            break;
        case 0xaf: /* CHECKMULTISIGVERIFY */
            if (!op_checkmultisig(it, true)) {
                return false;
            }
            break;
        case 0xb1: /* CLTV */
            if (!op_checklocktime(it)) {
                return false;
            }
            break;
        case 0xb2: /* CSV */
            if (!op_checksequence(it)) {
                return false;
            }
            break;
        default:
            set_error(it, "不支持的操作码");
            return false;
        }
    }

    if (it->exec_depth != 0) {
        set_error(it, "条件未闭合");
        return false;
    }
    return true;
}

/* ---- 公开接口 ---- */

bool dtc_script_is_push_only(const uint8_t *script, size_t len)
{
    size_t pos = 0;
    while (pos < len) {
        uint8_t op = script[pos++];
        if (op > 0x60) {
            return false;
        }
        const uint8_t *data;
        size_t datalen;
        if ((op <= 0x4b) || op == 0x4c || op == 0x4d || op == 0x4e) {
            if (!read_push(script, len, &pos, op, &data, &datalen)) {
                return false;
            }
        }
    }
    return true;
}

bool dtc_script_is_witness_program(const uint8_t *script, size_t len,
                                   uint8_t *witver_out)
{
    if (len < 4 || len > 42) {
        return false;
    }
    uint8_t op = script[0];
    uint8_t witver;
    if (op == 0x00) {
        witver = 0;
    } else if (op >= 0x51 && op <= 0x60) {
        witver = (uint8_t)(op - 0x50);
    } else {
        return false;
    }
    size_t proglen = script[1];
    if (proglen < 2 || proglen > 40 || proglen != len - 2) {
        return false;
    }
    if (witver_out != NULL) {
        *witver_out = witver;
    }
    return true;
}

/* P2SH 模式：OP_HASH160 <20 字节> OP_EQUAL */
static bool is_p2sh(const uint8_t *script, size_t len, const uint8_t **hash20)
{
    if (len != 23 || script[0] != 0xa9 || script[1] != 0x14 ||
        script[22] != 0x87) {
        return false;
    }
    if (hash20 != NULL) {
        *hash20 = script + 2;
    }
    return true;
}

bool dtc_script_verify(const dtc_tx *tx, size_t input_index,
                       const dtc_bytes *script_sig, const dtc_bytes *script_pubkey,
                       dtc_amount amount, const dtc_script_ctx *ctx, char *err,
                       size_t errcap)
{
    if (err != NULL && errcap > 0) {
        err[0] = '\0';
    }
    if (tx == NULL || input_index >= tx->vin_count) {
        return false;
    }

    /* 明确拒绝 witness 程序，避免 legacy 语义误判为真 */
    uint8_t witver = 0;
    if (dtc_script_is_witness_program(script_pubkey->data,
                                      script_pubkey->len, &witver)) {
        if (err != NULL) {
            (void)snprintf(err, errcap,
                           "witness v%u 程序尚未实现（本里程碑仅 legacy/P2SH）",
                           (unsigned)witver);
        }
        return false;
    }

    if (!dtc_script_is_push_only(script_sig->data, script_sig->len)) {
        if (err != NULL) {
            (void)snprintf(err, errcap, "scriptSig 必须是 push-only");
        }
        return false;
    }

    interp it;
    memset(&it, 0, sizeof(it));
    it.stack = (stack_item *)calloc(DTC_MAX_STACK_SIZE, sizeof(stack_item));
    it.altstack = (stack_item *)calloc(DTC_MAX_STACK_SIZE, sizeof(stack_item));
    if (it.stack == NULL || it.altstack == NULL) {
        free(it.stack);
        free(it.altstack);
        if (err != NULL) {
            (void)snprintf(err, errcap, "内存不足");
        }
        return false;
    }
    it.ctx = ctx;
    it.tx = tx;
    it.input_index = input_index;
    it.amount = amount;
    it.err = err;
    it.errcap = errcap;

    bool ok = eval_script(&it, script_sig->data, script_sig->len);

    /* P2SH：保存 scriptSig 最后一个 push 作为 redeem script */
    const uint8_t *expected_hash = NULL;
    bool p2sh = is_p2sh(script_pubkey->data, script_pubkey->len, &expected_hash);
    stack_item redeem;
    memset(&redeem, 0, sizeof(redeem));
    bool have_redeem = false;
    if (ok && p2sh && it.sp > 0) {
        redeem = it.stack[it.sp - 1];
        have_redeem = true;
    }

    if (ok) {
        ok = eval_script(&it, script_pubkey->data, script_pubkey->len);
    }

    if (ok) {
        stack_item *top;
        if (it.sp == 0) {
            set_error(&it, "脚本执行后栈为空");
            ok = false;
        } else if (!top_item(&it, &top) || !cast_bool(top)) {
            set_error(&it, "脚本结果为假");
            ok = false;
        }
    }

    if (ok && p2sh) {
        if (!have_redeem) {
            set_error(&it, "P2SH 缺少 redeem script");
            ok = false;
        } else {
            uint8_t hash[20];
            dtc_hash160(redeem.data, redeem.len, hash);
            if (memcmp(hash, expected_hash, 20) != 0) {
                set_error(&it, "P2SH redeem script 哈希不匹配");
                ok = false;
            } else if (dtc_script_is_witness_program(redeem.data, redeem.len,
                                                      &witver)) {
                set_error(&it, "P2SH 包裹的 witness 程序尚未实现");
                ok = false;
            } else {
                /* 弹出 scriptPubKey 产生的 true，留下参数栈执行 redeem */
                if (it.sp > 0) {
                    --it.sp;
                }
                ok = eval_script(&it, redeem.data, redeem.len);
                if (ok) {
                    stack_item *top;
                    if (it.sp == 0) {
                        set_error(&it, "redeem 执行后栈为空");
                        ok = false;
                    } else if (!top_item(&it, &top) || !cast_bool(top)) {
                        set_error(&it, "redeem 结果为假");
                        ok = false;
                    }
                }
            }
        }
    }

    /*
     * CLEANSTACK：全部执行完毕后栈上必须恰好剩一个 true。
     * Ditcoin 从高度 0 起强制该规则（比 Bitcoin legacy 更严格，
     * 防止依赖残留栈元素的脚本在跨实现间产生歧义）。
     */
    if (ok && it.sp != 1) {
        set_error(&it, "CLEANSTACK：执行后栈必须恰好剩 1 个元素");
        ok = false;
    }

    free(it.stack);
    free(it.altstack);
    return ok;
}
