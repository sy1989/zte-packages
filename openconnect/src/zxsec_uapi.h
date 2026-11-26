/*
 * zxsec_uapi.h - ZX279133 SEC 硬件加速私有 ABI（逆向还原版）
 *
 * 来源：从 D:/sg350h/1.3/mihomo（UPX 解包后的 Go 二进制）的 pclntab、
 *       类型元数据与反汇编代码还原。对应模块 zte/zx279133sec@v0.0.0。
 *
 * 状态：ioctl 命令号与 Info/Session 结构体是从二进制中"实证"提取的；
 *       OpRequest 的字段偏移来自 hwGCM.Seal/Open 的反汇编推导，
 *       使用前建议在实机上做一次最小 ioctl 验证（见配套文档）。
 *
 * 平台：aarch64 Linux (SG350H, kernel 7.3.4)
 */

#ifndef ZXSEC_UAPI_H
#define ZXSEC_UAPI_H

#include <stdint.h>
#include <sys/ioctl.h>

#define ZXSEC_DEV_SEC  "/dev/zx279133-sec"
#define ZXSEC_DEV_CTL  "/dev/zx279133-ctl"
#define ZXSEC_NPU_TUN  "/sys/bus/platform/devices/*.ethernet/npu_tun"

/* ---- ioctl 命令（从路由器实机 zx-sec-ctl 反汇编提取，权威值） ----
 * 注意：必须用硬编码常量，不要用 _IOR/_IOWR 宏。
 * 实测 musl SDK 的 <sys/ioctl.h> 中 _IOR/_IOWR 在本环境下把 size 编码成 4，
 * 导致 _IOR('Z',1,40) 展开为 0x80045a01（错误），ioctl 返回 ENOTTY。
 * 以下数值与 zx-sec-ctl 反汇编 (0x4024cc 等处) 逐字节一致，已在路由器验证。
 */
#define ZXSEC_IOC_INFO        0x80285a01  /* _IOR('Z',1,40)  实测 OK */
#define ZXSEC_IOC_SET_ARENA   0xc0085a02  /* _IOWR('Z',2,8) */
#define ZXSEC_IOC_ALLOC_SESS  0xc0505a03  /* _IOWR('Z',3,80) */
#define ZXSEC_IOC_FREE_SESS   0x40045a04  /* _IOW('Z',4,4) */
#define ZXSEC_IOC_SUBMIT_BATCH 0xc0185a05 /* _IOWR('Z',5,24) */
#define ZXSEC_IOC_SUBMIT_ONE  0xc0405a06  /* _IOWR('Z',6,64) */

/* NPU TUN 控制设备：mihomo/hub.syncNPUTunDeviceIoctl 使用 */
#define ZTENPU_TUN_IOC_SET    0xc2604e0a  /* _IOWR('N',10,608) */

/* ---- 设备信息，40 字节，与 Go 类型 zx279133sec.Info 完全一致 ---- */
struct zxsec_info {
    uint32_t abi_version;    /* +0  实测为 1 */
    uint32_t queue_id;       /* +4  0 = PD0；也决定 min_hw_bytes（0→512, 非0→256） */
    uint32_t queue_depth;    /* +8  */
    uint32_t max_batch;      /* +12 实测 16（batch16 的来源） */
    uint32_t arena_size;     /* +16 mmap 长度，实测 0x200000 = 2MiB */
    uint32_t slot_size;      /* +20 实测 0x10000 = 64KiB，槽数 = arena/slot = 32 */
    uint32_t max_op_len;     /* +24 单次操作明文上限 */
    uint32_t max_sessions;   /* +28 实测 256 */
    uint64_t alg_mask;       /* +32 实测 0x1ffffe，bit 索引见下 */
};

/* alg_mask 的 bit 索引。
 *
 * 权威来源：usr/bin/zx-sec-ctl 反汇编。
 *  - INFO 打印函数在 0x40171c 有循环 `for (i=1; i<12; i++) if (mask>>i & 1)`
 *    ，按序打印 0x4039a0 处 11 个算法名指针；
 *  - SM4-CBC 的 KAT 在 0x401f04 调 alloc_sess(alg_bit=8, keylen=16)，
 *    与表里第 8 项 sm4-128-cbc 吻合，交叉验证了映射。
 */
#define ZXSEC_ALG_AES128_GCM_BIT 1   /* key 16 */
#define ZXSEC_ALG_AES256_GCM_BIT 2   /* key 32 */
#define ZXSEC_ALG_AES128_CCM_BIT 3   /* key 16 */
#define ZXSEC_ALG_AES128_CTR_BIT 4   /* key 16 */
#define ZXSEC_ALG_AES256_CTR_BIT 5   /* key 32 */
#define ZXSEC_ALG_AES128_CBC_BIT 6   /* key 16 —— 无 tag、无 AAD */
#define ZXSEC_ALG_AES256_CBC_BIT 7   /* key 32 */
#define ZXSEC_ALG_SM4_128_CBC_BIT 8  /* key 16 */
#define ZXSEC_ALG_SM4_128_CTR_BIT 9  /* key 16 */
#define ZXSEC_ALG_HMAC_SHA256_BIT 10
#define ZXSEC_ALG_HMAC_SM3_BIT 11

/* mihomo 里用过的 192 位 GCM（不在 zx-sec-ctl 的 11 项表里） */
#define ZXSEC_ALG_AES192_GCM_BIT 12  /* key 24 */

/* SET_ARENA 参数：8 字节 { uint32 arena_bytes; uint32 reserved } */
struct zxsec_set_arena {
    uint32_t arena_bytes;
    uint32_t reserved;
};

/* ALLOC_SESS 参数：80 字节
 * 反汇编：stp w1,w3,[sp]; memmove(sp+0x10, key, keylen); ioctl;
 *         sessID = *(uint32*)(sp+0x08)
 */
struct zxsec_alloc_sess {
    uint32_t alg_bit;    /* +0  alg_mask 的 bit 索引，不是密钥长度 */
    uint32_t key_len;    /* +4  16/24/32 */
    uint32_t sess_id;    /* +8  输出：分配到的硬件会话号 */
    uint32_t reserved0;  /* +12 */
    uint8_t  key[64];    /* +16 最长 32 字节有效 */
};

/* FREE_SESS 参数：4 字节 session id */
typedef uint32_t zxsec_sess_id_t;

/* SUBMIT_ONE 参数：64 字节（GCM 请求）
 * 偏移由 (*hwGCM).Seal / Open 中对 sp+0x98 这块栈内存的写入还原。
 */
struct zxsec_op_request {
    uint32_t sess_id;     /* +0  已分配的硬件会话号 */
    uint32_t word4;       /* +4  字节 4 保留；字节 5=tag_len(16)；字节 6..7=aad_len */
    uint32_t arena_off;   /* +8  明文在 mmap arena 中的偏移（slot 基址 + 128） */
    uint32_t reserved0;   /* +12 */
    uint32_t slot_off;    /* +16 归还槽位时使用的 slot 基址 */
    uint32_t data_len;    /* +20 明文长度 */
    uint32_t reserved1;   /* +24 */
    int32_t  result;      /* +28 输出：0 成功 / 返回的密文长度 / 负 errno */
    uint8_t  nonce[12];   /* +32 内联 12 字节 nonce */
    uint8_t  reserved2[20]; /* +44..63 */
};

/* word4 的字节访问（小端 aarch64） */
#define ZXSEC_REQ_SET_TAGLEN(r, v)  (((uint8_t *)&(r)->word4)[1] = (v))
#define ZXSEC_REQ_SET_AADLEN(r, v)  ((*(uint16_t *)((uint8_t *)&(r)->word4 + 2)) = (v))

/* 上面的 C 结构因 tag_len 与 pad 重叠容易写错，下面是精确字节布局版本（推荐手工填充）：
 *   offset 0  : uint32 sess_id
 *   offset 4  : uint32 0
 *   offset 5  : uint8  16
 *   offset 6  : uint16 aad_len
 *   offset 8  : uint32 arena_off
 *   offset 12 : uint32 0
 *   offset 16 : uint32 slot_off
 *   offset 20 : uint32 data_len
 *   offset 24 : uint32 0
 *   offset 28 : int32  result (out)
 *   offset 32 : uint8  nonce[12]
 *   offset 44 : 20 字节保留（全零）
 */
#define ZXSEC_REQ_SIZE 64

/* SUBMIT_BATCH 参数：24 字节 */
struct zxsec_submit_batch {
    uint64_t reqs_ptr;    /* +0  指向连续的 struct zxsec_op_request 数组 */
    uint32_t count;       /* +8  1..max_batch(16) */
    uint32_t reserved;    /* +12 */
    uint32_t result;      /* +16 输出：非 0 表示有失败项 */
    uint32_t reserved2;   /* +20 */
};

/* ---- 用户态调用骨架（伪代码，需实测校准） ---- */
/*
 * int fd = open(ZXSEC_DEV_SEC, O_RDWR|O_CLOEXEC);
 * struct zxsec_set_arena sa = { .arena_bytes = 2*1024*1024 };
 * ioctl(fd, ZXSEC_IOC_SET_ARENA, &sa);              // 可选，显式指定 arena 大小
 * struct zxsec_info info;
 * ioctl(fd, ZXSEC_IOC_INFO, &info);                 // abi_version 必须为 1
 * void *arena = mmap(NULL, info.arena_size, PROT_READ|PROT_WRITE,
 *                    MAP_SHARED, fd, 0);
 *
 * struct zxsec_alloc_sess as = { .alg_bit = ZXSEC_ALG_AES256_GCM_BIT,
 *                                .key_len = 32 };
 * memcpy(as.key, key, 32);
 * ioctl(fd, ZXSEC_IOC_ALLOC_SESS, &as);
 * uint32_t sid = as.sess_id;
 *
 * // 槽位管理由用户态自己维护：slot_size=64KiB，槽数=arena/slot。
 * // 槽 0..N-1 的基址 = slot_index * info.slot_size。
 * // 每个槽布局：[0..127] AAD；[128..128+pt_len] 明文；硬件追加 16B tag。
 *
 * uint8_t *slot = arena + slot_index * info.slot_size;
 * memcpy(slot, aad, aad_len);
 * memcpy(slot + 128, plain, pt_len);
 *
 * uint8_t reqbuf[ZXSEC_REQ_SIZE] = {0};
 * struct zxsec_op_request *r = (struct zxsec_op_request *)reqbuf;
 * r->sess_id = sid;
 * ZXSEC_REQ_SET_TAGLEN(r, 16);
 * ZXSEC_REQ_SET_AADLEN(r, aad_len);
 * r->arena_off = slot_index * info.slot_size + 128;
 * r->slot_off = slot_index * info.slot_size;
 * r->data_len = pt_len;
 * memcpy(r->nonce, nonce, 12);
 * ioctl(fd, ZXSEC_IOC_SUBMIT_ONE, reqbuf);
 * int out_len = r->result;   // >0 时密文在 slot+128
 *
 * ioctl(fd, ZXSEC_IOC_FREE_SESS, &sid);
 * munmap(arena, info.arena_size);
 * close(fd);
 */

#endif /* ZXSEC_UAPI_H */
