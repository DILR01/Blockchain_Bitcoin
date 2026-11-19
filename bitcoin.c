// 包含标准输入输出和字符串处理函数。
#include <stdio.h>
// 包含标准库中的内存、退出和随机数相关函数。
#include <stdlib.h>
// 包含字符串复制、比较和长度相关函数。
#include <string.h>
// 包含时间戳类型和时间读取函数。
#include <time.h>
// 包含SHA-256等哈希算法声明。
#include <openssl/sha.h>
// 包含椭圆曲线和ECDSA密钥操作声明。
#include <openssl/ec.h>
// 包含EVP数字签名操作声明。
#include <openssl/evp.h>
// 包含十六进制编码所需的整数类型声明。
#include <openssl/crypto.h>

// 定义区块链最多容纳的区块数量。
#define MAX_BLOCKS 16
// 定义区块最多容纳的交易数量。
#define MAX_TXS 8
// 定义交易中各文本字段的最大长度。
#define TX_TEXT_SIZE 128
// 定义ECDSA数字签名的最大长度。
#define SIG_MAX_SIZE 256
// 定义工作量证明难度为前导十六进制零的个数。
#define POW_DIFFICULTY 3

// 定义交易结构。
typedef struct {
    // 保存交易来源UTXO标识。
    char input[TX_TEXT_SIZE];
    // 保存交易发送方名称。
    char sender[TX_TEXT_SIZE];
    // 保存交易接收方名称。
    char recipient[TX_TEXT_SIZE];
    // 保存交易金额。
    long amount;
    // 保存交易DER格式ECDSA签名。
    unsigned char signature[SIG_MAX_SIZE];
    // 保存实际签名长度。
    size_t signature_size;
} Transaction;

// 定义区块结构。
typedef struct {
    // 保存区块高度。
    unsigned long index;
    // 保存区块创建时间。
    time_t timestamp;
    // 保存前一个区块的哈希。
    char previous_hash[65];
    // 保存区块中的Merkle根。
    char merkle_root[65];
    // 保存工作量证明随机数。
    unsigned long nonce;
    // 保存区块交易数量。
    size_t tx_count;
    // 保存区块交易数组。
    Transaction transactions[MAX_TXS];
    // 保存区块自身哈希。
    char hash[65];
} Block;

// 定义区块链结构。
typedef struct {
    // 保存链中区块数量。
    size_t block_count;
    // 保存区块数组。
    Block blocks[MAX_BLOCKS];
} Blockchain;

// 将字节数组转换为十六进制字符串。
static void bytes_to_hex(const unsigned char *bytes, size_t length, char output[65]) {
    // 定义十六进制字符表。
    static const char hex[] = "0123456789abcdef";
    // 遍历每一个字节。
    for (size_t i = 0; i < length; ++i) {
        // 写入当前字节的高四位。
        output[i * 2] = hex[(bytes[i] >> 4) & 15];
        // 写入当前字节的低四位。
        output[i * 2 + 1] = hex[bytes[i] & 15];
    }
    // 在十六进制字符串末尾添加空字符。
    output[length * 2] = '\0';
}

// 计算任意数据的SHA-256哈希。
static void sha256_data(const void *data, size_t length, char output[65]) {
    // 分配SHA-256哈希结果缓冲区。
    unsigned char digest[SHA256_DIGEST_LENGTH];
    // 调用OpenSSL计算SHA-256。
    SHA256((const unsigned char *)data, length, digest);
    // 将二进制哈希转换为十六进制。
    bytes_to_hex(digest, SHA256_DIGEST_LENGTH, output);
}

// 计算交易的序列化内容哈希。
static void hash_transaction(const Transaction *tx, char output[65]) {
    // 准备交易序列化缓冲区。
    char data[600];
    // 序列化交易字段并写入缓冲区。
    snprintf(data, sizeof(data), "%s|%s|%s|%ld", tx->input, tx->sender, tx->recipient, tx->amount);
    // 使用SHA-256计算交易哈希。
    sha256_data(data, strlen(data), output);
}

// 计算区块交易集合的Merkle根。
static void calculate_merkle_root(const Block *block, char output[65]) {
    // 初始化Merkle层数组。
    char hashes[MAX_TXS][65];
    // 如果区块没有交易则使用空数据哈希。
    if (block->tx_count == 0) {
        // 计算空数据的哈希作为Merkle根。
        sha256_data("", 0, output);
        // 提前返回空交易结果。
        return;
    }
    // 为每笔交易计算叶子哈希。
    for (size_t i = 0; i < block->tx_count; ++i) {
        // 保存交易i的哈希。
        hash_transaction(&block->transactions[i], hashes[i]);
    }
    // 保存当前Merkle层节点数量。
    size_t count = block->tx_count;
    // 当仍有多个节点时继续向上合并。
    while (count > 1) {
        // 计算合并后的新层节点数。
        size_t next = (count + 1) / 2;
        // 遍历当前层相邻节点。
        for (size_t i = 0; i < next; ++i) {
            // 获取左侧节点索引。
            size_t left = i * 2;
            // 获取右侧节点索引并复制左侧值以处理奇数节点。
            size_t right = (left + 1 < count) ? left + 1 : left;
            // 拼接左右节点哈希。
            char pair[130];
            // 拷贝左侧哈希到拼接缓冲区。
            snprintf(pair, sizeof(pair), "%s%s", hashes[left], hashes[right]);
            // 计算配对节点的新哈希。
            sha256_data(pair, strlen(pair), hashes[i]);
        }
        // 更新当前Merkle层节点数量。
        count = next;
    }
    // 将最终Merkle根复制到输出参数。
    strcpy(output, hashes[0]);
}

// 计算区块头的哈希。
static void calculate_block_hash(const Block *block, char output[65]) {
    // 准备区块头序列化缓冲区。
    char data[512];
    // 序列化区块高度、时间、前哈希、Merkle根和随机数。
    snprintf(data, sizeof(data), "%lu|%lld|%s|%s|%lu",
             block->index, (long long)block->timestamp,
             block->previous_hash, block->merkle_root, block->nonce);
    // 使用SHA-256计算区块头哈希。
    sha256_data(data, strlen(data), output);
}

// 使用ECDSA执行工作量证明挖矿。
static void mine_block(Block *block) {
    // 重新计算区块Merkle根。
    calculate_merkle_root(block, block->merkle_root);
    // 初始化随机数为零。
    block->nonce = 0;
    // 准备难度前缀字符串。
    char prefix[POW_DIFFICULTY + 1];
    // 填充前导零字符。
    memset(prefix, '0', POW_DIFFICULTY);
    // 在难度前缀末尾添加空字符。
    prefix[POW_DIFFICULTY] = '\0';
    // 持续尝试随机数直到满足目标难度。
    for (;;) {
        // 计算当前随机数对应的区块哈希。
        calculate_block_hash(block, block->hash);
        // 检查哈希是否具有指定数量的前导零。
        if (strncmp(block->hash, prefix, POW_DIFFICULTY) == 0) {
            // 找到有效工作量证明后退出循环。
            break;
        }
        // 增加随机数继续尝试。
        ++block->nonce;
    }
}

// 创建ECDSA P-256密钥对。
static EVP_PKEY *create_key(void) {
    // 创建EC密钥生成上下文。
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    // 检查上下文是否创建成功。
    if (context == NULL) {
        // 返回空指针表示密钥创建失败。
        return NULL;
    }
    // 初始化密钥生成参数。
    if (EVP_PKEY_keygen_init(context) <= 0) {
        // 释放生成上下文。
        EVP_PKEY_CTX_free(context);
        // 返回空指针表示初始化失败。
        return NULL;
    }
    // 设置secp256k1椭圆曲线参数。
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_secp256k1) <= 0) {
        // 释放生成上下文。
        EVP_PKEY_CTX_free(context);
        // 返回空指针表示曲线设置失败。
        return NULL;
    }
    // 声明生成后的密钥指针。
    EVP_PKEY *key = NULL;
    // 执行密钥对生成。
    EVP_PKEY_keygen(context, &key);
    // 释放密钥生成上下文。
    EVP_PKEY_CTX_free(context);
    // 返回生成的密钥。
    return key;
}

// 对交易进行ECDSA SHA-256签名。
static int sign_transaction(EVP_PKEY *key, Transaction *tx) {
    // 准备交易签名数据缓冲区。
    char data[600];
    // 序列化交易核心字段。
    snprintf(data, sizeof(data), "%s|%s|%s|%ld", tx->input, tx->sender, tx->recipient, tx->amount);
    // 创建数字签名上下文。
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    // 检查上下文是否创建成功。
    if (context == NULL) {
        // 签名失败时返回零。
        return 0;
    }
    // 初始化ECDSA摘要签名流程。
    if (EVP_DigestSignInit(context, NULL, EVP_sha256(), NULL, key) <= 0) {
        // 释放签名上下文。
        EVP_MD_CTX_free(context);
        // 签名失败时返回零。
        return 0;
    }
    // 更新待签名摘要数据。
    if (EVP_DigestSignUpdate(context, data, strlen(data)) <= 0) {
        // 释放签名上下文。
        EVP_MD_CTX_free(context);
        // 签名失败时返回零。
        return 0;
    }
    // 获取签名所需缓冲区长度。
    size_t required = 0;
    // 使用空输出查询签名长度。
    EVP_DigestSignFinal(context, NULL, &required);
    // 防止签名长度超过固定缓冲区。
    if (required > SIG_MAX_SIZE) {
        // 释放签名上下文。
        EVP_MD_CTX_free(context);
        // 签名过长时返回零。
        return 0;
    }
    // 设置签名缓冲区容量为实际查询长度。
    tx->signature_size = required;
    // 写入交易签名并记录长度。
    if (EVP_DigestSignFinal(context, tx->signature, &tx->signature_size) <= 0) {
        // 释放签名上下文。
        EVP_MD_CTX_free(context);
        // 签名失败时返回零。
        return 0;
    }
    // 释放签名上下文。
    EVP_MD_CTX_free(context);
    // 签名成功时返回一。
    return 1;
}

// 验证交易的ECDSA SHA-256签名。
static int verify_transaction(EVP_PKEY *key, const Transaction *tx) {
    // 准备待验证交易数据缓冲区。
    char data[600];
    // 序列化交易核心字段。
    snprintf(data, sizeof(data), "%s|%s|%s|%ld", tx->input, tx->sender, tx->recipient, tx->amount);
    // 创建数字验证上下文。
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    // 检查上下文是否创建成功。
    if (context == NULL) {
        // 验证失败时返回零。
        return 0;
    }
    // 初始化ECDSA摘要验证流程。
    if (EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, key) <= 0) {
        // 释放验证上下文。
        EVP_MD_CTX_free(context);
        // 验证失败时返回零。
        return 0;
    }
    // 更新待验证摘要数据。
    if (EVP_DigestVerifyUpdate(context, data, strlen(data)) <= 0) {
        // 释放验证上下文。
        EVP_MD_CTX_free(context);
        // 验证失败时返回零。
        return 0;
    }
    // 执行ECDSA签名验证并保存结果。
    int valid = EVP_DigestVerifyFinal(context, tx->signature, tx->signature_size);
    // 释放验证上下文。
    EVP_MD_CTX_free(context);
    // 只有验证结果为一才接受交易。
    return valid == 1;
}

// 初始化区块链创世区块。
static void initialize_chain(Blockchain *chain) {
    // 创建创世区块并清零。
    Block genesis;
    // 清除创世区块全部内容。
    memset(&genesis, 0, sizeof(genesis));
    // 设置创世区块高度为零。
    genesis.index = 0;
    // 设置创世区块时间戳。
    genesis.timestamp = time(NULL);
    // 设置创世区块前哈希。
    strcpy(genesis.previous_hash, "0");
    // 设置创世区块交易数量为零。
    genesis.tx_count = 0;
    // 挖出创世区块工作量证明。
    mine_block(&genesis);
    // 初始化链区块数量。
    chain->block_count = 1;
    // 保存创世区块。
    chain->blocks[0] = genesis;
}

// 添加并挖出一个包含交易的新区块。
static int add_block(Blockchain *chain, Transaction *tx) {
    // 检查链是否已达到区块数量上限。
    if (chain->block_count >= MAX_BLOCKS) {
        // 满额时拒绝添加区块。
        return 0;
    }
    // 获取前一个区块指针。
    Block *previous = &chain->blocks[chain->block_count - 1];
    // 创建并清零新区块。
    Block block;
    // 清除新区块全部内容。
    memset(&block, 0, sizeof(block));
    // 设置新区块高度。
    block.index = chain->block_count;
    // 设置新区块时间戳。
    block.timestamp = time(NULL);
    // 复制前一区块哈希。
    strcpy(block.previous_hash, previous->hash);
    // 设置新区块交易数量。
    block.tx_count = 1;
    // 保存交易到新区块。
    block.transactions[0] = *tx;
    // 挖出新区块工作量证明。
    mine_block(&block);
    // 保存新区块到区块链。
    chain->blocks[chain->block_count++] = block;
    // 返回区块添加成功。
    return 1;
}

// 验证整条区块链的哈希、链接和工作量证明。
static int verify_chain(const Blockchain *chain) {
    // 检查链是否至少包含创世区块。
    if (chain->block_count == 0) {
        // 空链验证失败。
        return 0;
    }
    // 准备用于重新计算的区块哈希。
    char recomputed[65];
    // 遍历链中的全部区块。
    for (size_t i = 0; i < chain->block_count; ++i) {
        // 获取只读区块指针。
        const Block *block = &chain->blocks[i];
        // 重新计算区块Merkle根。
        char merkle[65];
        // 计算区块Merkle根。
        calculate_merkle_root(block, merkle);
        // 检查Merkle根是否被篡改。
        if (strcmp(block->merkle_root, merkle) != 0) {
            // Merkle根异常时验证失败。
            return 0;
        }
        // 重新计算区块头哈希。
        calculate_block_hash(block, recomputed);
        // 检查区块哈希是否被篡改。
        if (strcmp(block->hash, recomputed) != 0) {
            // 区块哈希异常时验证失败。
            return 0;
        }
        // 检查区块哈希是否满足挖矿难度。
        for (size_t zero = 0; zero < POW_DIFFICULTY; ++zero) {
            // 任意位置不是零都会验证失败。
            if (block->hash[zero] != '0') {
                // 工作量证明无效时验证失败。
                return 0;
            }
        }
        // 创世区块不检查前哈希链接。
        if (i == 0) {
            // 检查创世区块高度。
            if (block->index != 0) {
                // 创世高度异常时验证失败。
                return 0;
            }
            // 继续检查下一个区块。
            continue;
        }
        // 获取前一个区块指针。
        const Block *previous = &chain->blocks[i - 1];
        // 检查区块高度是否连续。
        if (block->index != previous->index + 1) {
            // 区块高度异常时验证失败。
            return 0;
        }
        // 检查新区块是否链接到前一区块哈希。
        if (strcmp(block->previous_hash, previous->hash) != 0) {
            // 哈希链断裂时验证失败。
            return 0;
        }
    }
    // 全部检查通过时返回成功。
    return 1;
}

// 打印区块链摘要和交易签名状态。
static void print_chain(const Blockchain *chain) {
    // 遍历并打印全部区块。
    for (size_t i = 0; i < chain->block_count; ++i) {
        // 获取当前区块指针。
        const Block *block = &chain->blocks[i];
        // 打印区块基本信息。
        printf("区块 %lu: nonce=%lu hash=%s\n", block->index, block->nonce, block->hash);
        // 遍历并打印区块交易。
        for (size_t j = 0; j < block->tx_count; ++j) {
            // 获取交易只读指针。
            const Transaction *tx = &block->transactions[j];
            // 打印交易来源、发送方、接收方和金额。
            printf(" 交易: %s %ld %s -> %s\n", tx->input, tx->amount, tx->sender, tx->recipient);
        }
    }
}

// 演示正常区块链创建、签名、挖矿和验证。
static void run_demo(void) {
    // 创建区块链并初始化创世区块。
    Blockchain chain;
    // 初始化创世区块。
    initialize_chain(&chain);
    // 创建Alice的ECDSA密钥。
    EVP_PKEY *alice = create_key();
    // 棉查密钥是否创建成功。
    if (alice == NULL) {
        // 密钥创建失败时打印错误。
        fprintf(stderr, "无法创建ECDSA密钥\n");
        // 退出演示函数。
        return;
    }
    // 创建第一笔交易并清零。
    Transaction tx1;
    // 清除交易结构。
    memset(&tx1, 0, sizeof(tx1));
    // 设置交易UTXO来源。
    strcpy(tx1.input, "alice-utxo-001");
    // 设置交易发送方。
    strcpy(tx1.sender, "Alice");
    // 设置交易接收方。
    strcpy(tx1.recipient, "Bob");
    // 设置交易金额。
    tx1.amount = 10;
    // 对第一笔交易签名。
    sign_transaction(alice, &tx1);
    // 检查第一笔交易签名。
    printf("交易1签名验证: %s\n", verify_transaction(alice, &tx1) ? "通过" : "失败");
    // 将第一笔交易加入区块链。
    add_block(&chain, &tx1);
    // 创建第二笔交易并清零。
    Transaction tx2;
    // 清除交易结构。
    memset(&tx2, 0, sizeof(tx2));
    // 设置第二笔交易UTXO来源。
    strcpy(tx2.input, "bob-utxo-001");
    // 设置第二笔交易发送方。
    strcpy(tx2.sender, "Bob");
    // 设置第二笔交易接收方。
    strcpy(tx2.recipient, "Carol");
    // 设置第二笔交易金额。
    tx2.amount = 4;
    // 对第二笔交易签名。
    sign_transaction(alice, &tx2);
    // 将第二笔交易加入区块链。
    add_block(&chain, &tx2);
    // 打印区块链摘要。
    print_chain(&chain);
    // 打印整链完整性验证结果。
    printf("完整链验证: %s\n", verify_chain(&chain) ? "通过" : "失败");
    // 释放Alice密钥。
    EVP_PKEY_free(alice);
}

// 演示篡改历史区块后链验证失败。
static void run_tamper_demo(void) {
    // 创建区块链并初始化创世区块。
    Blockchain chain;
    // 初始化创世区块。
    initialize_chain(&chain);
    // 创建密钥用于交易签名。
    EVP_PKEY *key = create_key();
    // 棉查密钥是否创建成功。
    if (key == NULL) {
        // 密钥失败时打印错误。
        fprintf(stderr, "无法创建ECDSA密钥\n");
        // 退出篡改演示。
        return;
    }
    // 创建用于篡改演示的交易。
    Transaction tx;
    // 清除交易结构。
    memset(&tx, 0, sizeof(tx));
    // 设置交易UTXO来源。
    strcpy(tx.input, "utxo-original");
    // 设置交易发送方。
    strcpy(tx.sender, "Alice");
    // 设置交易接收方。
    strcpy(tx.recipient, "Bob");
    // 设置交易金额。
    tx.amount = 100;
    // 签名交易。
    sign_transaction(key, &tx);
    // 添加交易区块。
    add_block(&chain, &tx);
    // 篡改区块交易金额。
    chain.blocks[1].transactions[0].amount = 999;
    // 打印篡改前原始摘要。
    printf("篡改区块交易金额为999后验证:\n");
    // 打印篡改后完整性验证结果。
    printf("篡改检测: %s\n", verify_chain(&chain) ? "未检测到篡改" : "检测到篡改，链被拒绝");
    // 释放密钥。
    EVP_PKEY_free(key);
}

// 演示双花攻击及UTXO防御。
static void run_double_spend_demo(void) {
    // 创建用于交易签名的密钥。
    EVP_PKEY *key = create_key();
    // 棉查密钥是否创建成功。
    if (key == NULL) {
        // 密钥失败时打印错误。
        fprintf(stderr, "无法创建ECDSA密钥\n");
        // 退出双花演示。
        return;
    }
    // 定义已花费UTXO集合。
    char spent[8][TX_TEXT_SIZE];
    // 初始化已花费UTXO数量。
    size_t spent_count = 0;
    // 创建第一笔双花候选交易。
    Transaction first;
    // 清除第一笔交易。
    memset(&first, 0, sizeof(first));
    // 设置第一笔交易来源。
    strcpy(first.input, "alice-utxo-001");
    // 设置第一笔发送方。
    strcpy(first.sender, "Alice");
    // 设置第一笔接收方。
    strcpy(first.recipient, "Bob");
    // 设置第一笔金额。
    first.amount = 100;
    // 签名第一笔交易。
    sign_transaction(key, &first);
    // 创建第二笔双花候选交易。
    Transaction second;
    // 清除第二笔交易。
    memset(&second, 0, sizeof(second));
    // 设置第二笔交易相同来源。
    strcpy(second.input, "alice-utxo-001");
    // 设置第二笔发送方。
    strcpy(second.sender, "Alice");
    // 设置第二笔接收方。
    strcpy(second.recipient, "Mallory");
    // 设置第二笔金额。
    second.amount = 100;
    // 签名第二笔交易。
    sign_transaction(key, &second);
    // 检查第一笔交易签名。
    if (verify_transaction(key, &first)) {
        // 记录第一笔UTXO为已花费。
        strcpy(spent[spent_count++], first.input);
        // 打印第一笔交易被接受。
        printf("交易A: 签名有效，UTXO首次花费，被接受\n");
    }
    // 声明第二笔交易是否重复花费。
    int duplicate = 0;
    // 检查UTXO是否已在已花费集合中。
    for (size_t i = 0; i < spent_count; ++i) {
        // 比较第二笔交易输入和已花费记录。
        if (strcmp(spent[i], second.input) == 0) {
            // 标记为重复花费。
            duplicate = 1;
            // 找到重复项后停止查找。
            break;
        }
    }
    // 检查第二笔交易签名和重复花费状态。
    if (verify_transaction(key, &second) && !duplicate) {
        // 未重复时接受交易并记录UTXO。
        strcpy(spent[spent_count++], second.input);
        // 打印意外接受结果。
        printf("交易B: 被意外接受\n");
    } else {
        // 重复花费或签名无效时拒绝。
        printf("交易B: 签名有效但UTXO已花费，被节点拒绝\n");
    }
    // 释放密钥。
    EVP_PKEY_free(key);
}

// 程序入口并根据参数选择演示模式。
int main(int argc, char **argv) {
    // 初始化OpenSSL遗留算法支持。
    OpenSSL_add_all_algorithms();
    // 检查是否请求篡改演示。
    if (argc == 2 && strcmp(argv[1], "tamper") == 0) {
        // 运行篡改历史区块演示。
        run_tamper_demo();
        // 正常结束程序。
        return 0;
    }
    // 检查是否请求双花演示。
    if (argc == 2 && strcmp(argv[1], "attack") == 0) {
        // 运行双花攻击演示。
        run_double_spend_demo();
        // 正常结束程序。
        return 0;
    }
    // 检查是否存在未知参数。
    if (argc == 2 && strcmp(argv[1], "demo") != 0) {
        // 打印有效命令行用法。
        fprintf(stderr, "用法: %s [demo|tamper|attack]\n", argv[0]);
        // 对未知参数返回失败状态。
        return 1;
    }
    // 运行默认区块链演示。
    run_demo();
    // 正常结束程序。
    return 0;
}
