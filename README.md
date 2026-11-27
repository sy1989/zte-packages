# zte-packages

ZTE SG350H（ZX279133）安全引擎（ZXSEC）相关的 OpenWrt 软件包，按 feed 的方式组织，三个包都在仓库根目录：

| 目录 | 包 | 说明 |
|---|---|---|
| `openssl/` | `libopenssl`（core 包） | OpenSSL 3.5.7，额外带两个 TLS 密钥回调钩子（弱符号，不影响未链接回调的程序）：160 号暴露 TLS1.2/DTLS1.2 密钥，170 号暴露 TLS1.3 application traffic key + 12B static IV。 |
| `openconnect/` | `openconnect` | OpenConnect 9.12，DTLS 与 CSTP(TCP) 数据面可选由自管记录层接管，通过 `/dev/zx279133-sec` 的 `SUBMIT_BATCH` 批量加解密（≤16 条/次），线上格式不变。CSTP 同时支持 TLS1.2 与 TLS1.3（AES-GCM），DTLS 走 DTLS1.2。 |
| `gnutls/` | `libgnutls` | GnuTLS 3.8.10，带 `_gnutls_set_keys()`（TLS1.2/DTLS1.2）与 `_tls13_set_keys()`（TLS1.3）两个密钥钩子和记录序号导出补丁；openconnect 的 GnuTLS 后端靠它把 DTLS/CSTP 记录交给 ZXSEC。 |

> openconnect 的 `DEPENDS` 里有 `+vpnc-scripts`（提供 `/lib/netifd/vpnc-script`），这个包来自官方 packages feed，本仓库不收录。

> 版本是**故意钉死**的：补丁都针对 openssl 3.5.7 / openconnect 9.12 / gnutls 3.8.10 生成；OpenSSL 与 GnuTLS 两条路径都已完成交叉编译和实机 A/B 验证。升级版本需要重新生成补丁（见文末）。
>
> 仓库历史按两段组织：**第一个 commit 是三个上游包的原始文件**（openssl 3.5.9 / openconnect 9.21 / gnutls 3.8.10），**第二个 commit 才是本项目的改动**（版本钉到 3.5.7 / 9.12、openconnect 的 ZXSEC 补丁与新增源码、后端选择）。看 `git diff HEAD~1` 就是全部 delta。

## 目录结构

```
openssl/
├── Makefile
├── Config.in
├── files/                 # openssl.cnf 片段、init 脚本（上游）
└── patches/
    ├── 010..510           # 上游 OpenWrt 补丁（未改动）
    └── 160-zxsec-tls12-keyhook.patch   # 本项目新增

openconnect/
├── Makefile
├── Config.in              # TLS 后端选择（两个后端都带 ZXSEC 记录层）
├── files/                 # netifd proto 脚本、wrapper（上游）
├── patches/
│   ├── 100-add-zxsec-dtls-flag.patch     # openconnect-internal.h: zxsec_dtls_active
│   ├── 110-dtls-batch-mainloop.patch     # dtls.c: glue 初始化 + RX/TX 批量分支
│   ├── 120-openssl-dtls-gate.patch       # openssl-dtls.c: 握手后 gate 检查
│   ├── 130-build-add-zxsec-sources.patch # Makefile.in: 对象与 .lo 规则
│   ├── 140-gnutls-record-layer.patch    # gnutls.c/gnutls-dtls.c: GnuTLS 后端接入
│   └── 150-openssl-cstp-hook.patch       # openssl.c: 接管点 + ssl_* 接入记录层
└── src/                   # 新增源文件（tarball 里没有，Build/Prepare 时拷入）
    ├── zxsec-record.c/.h
    ├── zxsec-glue.c/.h
    └── zxsec_uapi.h

gnutls/
├── Makefile
├── Config.in
└── patches/
    ├── 010..030            # 上游 OpenWrt 补丁（未改动）
    ├── 100-zxsec-key-hook.patch  # 本项目新增：导出 TLS1.2 密钥与记录序号
    └── 110-zxsec-tls13-keyhook.patch  # 本项目新增：导出 TLS1.3 application key + 12B IV
```

三个包目录各自带 `Makefile`，仓库根目录不需要额外 Makefile（OpenWrt feed 只要求包目录里有 Makefile，扫描深度 5 层）。

## 用法

### 1. 一键接入（推荐，防拉错包）

在 **SDK 根目录**执行仓库自带的脚本：

```sh
sh /path/to/zte-packages/setup-feed.sh
# 或显式指定仓库路径
sh /path/to/zte-packages/setup-feed.sh /path/to/zte-packages
```

脚本做四件事，可重复执行（幂等）：

1. 在 `feeds.conf` **顶部**写 `src-link zte <仓库路径>`（已存在则改写，不重复追加）。
2. 清掉已装的 `openconnect` / `gnutls` 符号链接——这步很关键：`scripts/feeds` 的
   `install_src()` 见到包已安装（`installed` 标志）会**直接跳过**，不解掉旧链就会
   继续使用官方 feed 的包。
3. `./scripts/feeds update zte` + `./scripts/feeds install -p zte openconnect libgnutls`，
   用 `-p zte` 强制从本仓库选包（官方 `packages` feed 里也有同名的
   `openconnect` / `gnutls`，不指定就会抢先被选中）。
4. 整目录替换 core 包 `package/libs/openssl`（feed 的同名包覆盖不了 core 包）。

脚本末尾会打印 13 项 PASS/FAIL：验证 `package/feeds/zte/` 下的链接确实指向本仓库、
没有官方同名链接残留、三个包的版本钉死、三个关键补丁都在、双后端选项存在。
**有任何 FAIL 就不要继续编译**，按提示检查 `feeds.conf` 和链接指向。

### 2. 手动接入（等价步骤）

如果不想用脚本，按同样顺序手做：

```sh
# feeds.conf 顶部（不是追加到末尾）：
#   src-link zte /path/to/zte-packages
./scripts/feeds uninstall openconnect libgnutls          # 先解掉已装的官方包
rm -f package/feeds/*/openconnect package/feeds/*/gnutls package/feeds/*/libgnutls
./scripts/feeds update zte
./scripts/feeds install -p zte openconnect
./scripts/feeds install -p zte libgnutls
```

注意不能用 `./scripts/feeds install -a` 之后再来装我们的——那样官方同名包已安装，
`-p zte` 也会被 `installed` 标志挡掉。要么先 `uninstall`，要么一开始就只 `-p zte` 装这几个。

菜单里：`Network` → `VPN` → `openconnect`，再进 `Configuration` → `TLS backend` 选后端：

| 选项 | 说明 |
|---|---|
| `GnuTLS + ZXSEC record layer (default)`（默认） | DTLS 与 CSTP/TCP 都走批量记录层。依赖本仓库 `gnutls/`（带密钥钩子）和 `libtasn1`。运行时 `ZXSEC_DISABLE=1` 可回退到原生 GnuTLS 数据面。 |
| `OpenSSL + ZXSEC record layer` | 同样的批量记录层，密钥来自本仓库 `openssl/` 的 TLS1.2/TLS1.3 key hook（160/170 号补丁）。 |

两个后端默认都启用硬件加速；切换后端仍会触发重新编译（`PKG_CONFIG_DEPENDS`）。
两个后端是同一个包的两个构建分支，切后端会触发重新编译（`PKG_CONFIG_DEPENDS`），但**不会**自动清 build_dir，切换后建议 `make package/openconnect/clean` 一次。

### 3. openssl（core 包，必须替换而不是装 feed）

OpenSSL 是 OpenWrt 的 **core 包**，feed 里的同名包不会覆盖它。要带上密钥钩子，必须整目录替换构建树里的那份：

```sh
rm -rf package/libs/openssl
mkdir -p package/libs/openssl
cp -a /path/to/zte-packages/openssl/. package/libs/openssl/
```

注意结尾的 `/.`：写成 `cp -a .../openssl package/libs/openssl` 在目标目录已存在时会嵌套成 `package/libs/openssl/openssl`，补丁根本不生效。也别只复制单个 patch 了事——本仓库的 openssl 版本钉在 3.5.7，和官方 3.5.9 的补丁集不同。

替换后建议 `make package/libs/openssl/clean` 再编译，确保 libssl 真的重建。

### 4. 编译

```sh
make package/libs/openssl/compile V=s
make package/openconnect/compile V=s
```

### 5. 确认没拉错包

接入后、编译前先看链接指向（脚本已经自动验过，手工接入时自己核对）：

```sh
readlink -f package/feeds/zte/openconnect   # 应指向 <仓库>/openconnect
readlink -f package/feeds/zte/gnutls        # 应指向 <仓库>/gnutls
ls  package/feeds/packages/openconnect      # 应不存在（报错才对）
grep PKG_VERSION package/feeds/zte/openconnect/Makefile   # :=9.12
grep PKG_VERSION package/libs/openssl/Makefile            # :=3.5.7
```

编译后从日志确认用的是我们的源码和补丁：

```sh
grep -E 'openconnect-9\.12|gnutls-3\.8\.10|openssl-3\.5\.7' build_dir/.../config.log
# 编译输出里应能看到 100-add-zxsec-dtls-flag / 140-gnutls-record-layer 等 patch 被应用
```

运行时看握手日志（任一后端启用即说明 keyhook + 记录层都生效）：

```
ZXSEC: CSTP batch record layer ENABLED (AES-128-GCM)
ZXSEC: DTLS batch record layer ENABLED (AES-128-GCM)
```

若只看到 `keys not captured by keyhook ... batching disabled`，说明库不是本仓库打了钩子的版本（混用了 stock `libssl`/`libgnutls`），此时会安全回退原生数据面——回到第 1 步用脚本重新接入。

## 补丁做了什么

### openssl：一个弱符号钩子

`ssl/t1_enc.c` 的 `tls1_change_cipher_state()` 末尾、`ssl_set_new_record_layer()` 之前插入：

```c
extern void oc_zxsec_on_keys(SSL *, int is_dtls, int is_write, uint16_t epoch,
                             const unsigned char *key, size_t key_len,
                             const unsigned char *iv, size_t iv_len)
        __attribute__((weak));
```

- 仅 TLS≤1.2 且 `EVP_CIPH_GCM_MODE` 时触发；TLS1.3 走 `tls13_change_cipher_state()`，由 170 号补丁另行挂钩。
- 没链接回调时行为与官方 OpenSSL 完全一致。

### openssl：TLS1.3 密钥钩子（170 号补丁）

`ssl/tls13_enc.c` 的 `tls13_change_cipher_state()` 末尾、`ssl_set_new_record_layer()`
之前插入，只在 **application 保护级别**（`(which & (SSL3_CC_EARLY|SSL3_CC_HANDSHAKE)) == 0`）
且 GCM 时触发，把 key + 12B static IV 交给弱符号回调：

```c
extern void oc_zxsec_on_keys13(SSL *, int is_write,
                               const unsigned char *key, size_t key_len,
                               const unsigned char *iv, size_t iv_len)
        __attribute__((weak));
```

- handshake/early traffic key 不经过回调（接管点在握手完成之后，用不到它们）；
- KeyUpdate 换 key 走 `tls13_update_key()`，同样不经过回调——记录层读方向遇到
  inner handshake 记录会断线重连，所以收不到 rekey 也不会错乱。

### openconnect：接管 DTLS 数据面

- `dtls_setup()` 里初始化 glue（打开 `/dev/zx279133-sec`、mmap arena、建会话）；
- `dtls_mainloop()` 的 RX 用 `recvmmsg` 收一批数据报、按记录头展开、一次 `SUBMIT_BATCH` 解密，再按 `AC_PKT_*` 分发；
- TX 一次榨干 `outgoing_queue`（≤16 包）→ 一次 `SUBMIT_BATCH` → `sendmmsg`；
- 只有协商出 `DTLS1.2 + AES-GCM` 且设备可用时才接管，其余情况原样走 libssl；压缩开启时自动回落逐包路径。

`Makefile.in` 补丁只增加两个对象和两条 `.lo` 规则。**不要**同时改 `Makefile.am`：那样 `Makefile.am` 会比 `Makefile.in` 新，make 会尝试调用 automake 重新生成（OpenWrt 构建环境没有 automake），直接 `Error 127`。

### openconnect：CSTP/TCP 通道（150 号补丁）

DTLS 之外，CSTP（TCP 443 上的 TLS）也接了同一套记录层，做法比 DTLS 简单：

- 接管点在 `openssl.c` 的 `openconnect_openssl_connect()` 尾部——TLS 握手刚完成、
  认证 POST 还没发。`zxsec_glue_tls_bind()` 在那里装 key、做 gate 检查
  （TLS1.2 或 TLS1.3 + AES-GCM，按密钥钩子送来的 key 形态自动区分）；`openconnect_close_https()` 里
  `zxsec_glue_tls_unbind()` 把状态清干净（否则下一个 `SSL *` 复用同一地址会被
  误判为已接管）；
- `openssl.c` 的 `ssl_read/write/gets` 与 `ssl_nonblock_read/write` 在 `dtls=0`
  且已激活时转到 `zxsec_cstp_*()`，所以认证 POST、HTTP CONNECT、CSTP 数据、BYE
  全走记录层；
- 读方向没有数据报边界：64KB 缓冲 + 按 5B 头切记录，**先攒批再解密**——拿到第一条
  完整记录后继续非阻塞读，把 socket 里已到达的记录全抽进缓冲，攒到 16 条或读到
  EAGAIN 才发一次 `SUBMIT_BATCH`（对端没数据时第一次 top-up 就 EAGAIN，不增加延迟）。
  实测 42425 条记录只用了 2884 次提交，平均 14.7 条/批，84% 的批次满载 16 条；
- 明文按记录排队，上层的 1 字节读（HTTP 响应头）直接从队列取，语义与 `SSL_read` 一致；
- 写方向 seq 在 **TLS1.2 从 1 起**（CCS 后 libssl 已用 seq 0 发过 Finished）；**TLS1.3
  两方向都从 0 起**（application traffic key 是全新密钥空间，client Finished 用的是
  handshake traffic key，另一把 key）。之后所有 application_data 都经过本层；一次给
  超过 16KB（HTTP POST 正文）会按 16K 明文切块封装，非阻塞没写完时保留记录、下次用
  同一块数据重试只续写不重封；
- 写方向同样做了攒批，但**不能合并记录**：`ssl_write` 一次只给一个隧道包，记录层
  在写首帧时顺手把 `outgoing_queue` 里已就绪的包一起取走（FIFO，取不下就 requeue），
  **每帧封一条记录、多条记录走同一次 `SUBMIT_BATCH`**。实测 30 Mbps 上行 1389 次提交
  封了 16865 条记录，平均 12.1 条/批，多数批次满载 16 条。

> 为什么不能把多帧并进一条 16K 记录：ocserv 的 `parse_cstp_data()` 有硬校验
> `buf_size == 8 + pktlen`（`tlslib.c` 一次 `gnutls_record_recv` 只返回一条记录），
> 一条记录里塞两个 CSTP 帧会直接 `unexpected CSTP length` → worker 退出 →
> 客户端收到 DISCONNECT。所以“记录 = 一个 CSTP 帧”是服务端强制的边界。

> 接管点为什么必须在握手完成处、而不是 CONNECT 之前：认证 POST 也是应用记录，
> 它们已经把 seq 用掉了。若等到 CONNECT 前才 bind、从 seq=1 重新计数，服务端会因为
> nonce/AAD 里的 seq 不匹配丢弃第一条记录——现象是 `Error fetching HTTPS response`
> 加一次自动重连（新连接上 CONNECT 恰好是第一条应用记录，所以又成功了）。

与 DTLS 的取舍：TCP 记录通常是 16KB，比 DTLS 的 1.4KB 大一个数量级；但实测
ocserv 下发的记录普遍只有 ~1KB，所以读方向的攒批是主要收益。写方向受“记录 = 一个
CSTP 帧”的限制只能攒 ioctl、不能攒记录，收益主要来自把每批的描述符提交次数从
“每包一次”降到“每 12~16 包一次”。

## GnuTLS 后端

GnuTLS 走的是与 OpenSSL **相同的自管记录层**，不是注册 AEAD 后端：

1. `gnutls/patches/100-zxsec-key-hook.patch` 在 `_gnutls_set_keys()` 末尾调用弱符号
   `oc_zxsec_gnutls_on_keys()`，把 TLS1.2/DTLS1.2 AES-GCM 的最终密钥、4 字节 salt、
   epoch 交给 openconnect；另外导出 `oc_zxsec_gnutls_get_seq()` 供握手后对齐写序号。
2. `gnutls/patches/110-zxsec-tls13-keyhook.patch` 在 `_tls13_set_keys()` 末尾调用
   弱符号 `oc_zxsec_gnutls13_on_keys()`，只在 `stage == STAGE_APP`（application
   traffic key）且 AES-GCM 时把 key + 12B static IV 交给 openconnect——TLS1.3 的
   CSTP 接管靠它。KeyUpdate（`STAGE_UPD_*`）走 `_tls13_update_keys()`，不会触发钩子。
3. `openconnect/patches/140-gnutls-record-layer.patch` 在 `gnutls.c` 的 HTTP/CSTP 与
   `gnutls-dtls.c` 的 DTLS 握手完成点接管，读写全部转给同一套 `zxsec-glue.c`。
4. `zxsec-glue.c` 用 `OPENCONNECT_OPENSSL` / `OPENCONNECT_GNUTLS` 条件编译区分
   会话对象和 gate 检查；`zxsec-record.c` 的 nonce/AAD/批量提交对两个后端完全一致。
   openconnect 链接时加 `-Wl,--export-dynamic`，让动态 `libgnutls.so` 能解析到
   可执行文件里的弱符号钩子。

关键点：GnuTLS 的握手记录数量不固定，`Finished` 之后的写序号不是固定的 1。
bind 时调用 `oc_zxsec_gnutls_get_seq()` 读取当前 `sequence_number`，避免第一条
application_data 记录因 nonce/AAD 里的 seq 不匹配被丢弃。

依赖由 `libgnutls` 自己拉起（nettle/gmp/libtasn1/p11-kit），包显式写 `+libgnutls
+libtasn1`。`gnutls/` 是上游 `libs/gnutls` 包（3.8.10）加一个本项目补丁。

**交叉编译验证**：GnuTLS 3.8.10（带 100 号补丁）与 openconnect 9.12（全部 6 个补丁）
用 SDK 的 aarch64/musl 工具链完整编译通过；`libgnutls.a` 中存在弱符号
`oc_zxsec_gnutls_on_keys` 与 `oc_zxsec_gnutls_get_seq`，产物 `openconnect` 中
`zxsec_*` 与两个钩子都是 `T` 全局符号，解释器为 `/lib/ld-musl-aarch64.so.1`。
`TARGET_LDFLAGS += -Wl,--export-dynamic` 保证动态 `libgnutls.so` 能解析到主程序的钩子。
同一套源码切到 OpenSSL 后端也重新编译通过，产物只含 `oc_zxsec_on_keys`，不含 GnuTLS 钩子。

**设备实测（SG350H / GnuTLS 3.8.10 / 30 Mbps 定速）**：同一个二进制用 `ZXSEC_DISABLE=1` 做基线。

| 场景 | 原生 GnuTLS（oc 核） | GnuTLS + ZXSEC（oc 核） | 降幅 | NPU `pd1_hw_fifo.enq` |
|---|---:|---:|---:|---:|
| CSTP/TCP 下行 | 0.297 | 0.145 | **-51%** | +68063（2723/s） |
| CSTP/TCP 上行 | 0.339 | 0.196 | **-42%** | +99302（3970/s） |
| DTLS 下行 | 0.293 | 0.150 | **-49%** | +70919（2836/s） |
| DTLS 上行 | 0.339 | 0.210 | **-38%** | +120100（4802/s） |

总 CPU（双核合计）也从 0.33–0.44 核降到 0.18–0.29 核；四组吞吐均稳定在 29.7–30.0 Mbps。DTLS 满速 `wget` 另测到 12.12 MB/s（加速）对 7.33 MB/s（原生）；FTP 式满速波动较大，以定速 A/B 为准。

## 验证

编译产物里应能看到钩子：

```sh
readelf -sW openconnect | grep -c zxsec_    # 约 46
```

设备上运行时：

```sh
grep -E "batch record layer ENABLED|Established DTLS" /tmp/oc.log
grep pd1_hw_fifo /sys/kernel/debug/zx279133-ipsec/stats   # enq 随流量增长
```

DTLS 与 CSTP 各有一行启用日志，跑 `--no-dtls` 时应只看到 CSTP 那行：

```
ZXSEC: DTLS batch record layer ENABLED (AES-128-GCM)
ZXSEC: CSTP batch record layer ENABLED (AES-128-GCM)
```

协商出 TLS1.3 时 CSTP 那行显示 `TLS1.3-AES-128-GCM` / `TLS1.3-AES-256-GCM`
（OpenSSL 后端为 `TLS_AES_128_GCM_SHA256` 等套件名）。

OpenSSL 后端括号里显示的是 `SSL_CIPHER_get_name()`（例如 `ECDHE-RSA-AES128-GCM-SHA256`），GnuTLS 后端显示 `AES-128-GCM` / `AES-256-GCM`。

回退到原生软件加密（同一个二进制）：

```sh
ZXSEC_DISABLE=1 openconnect ...
```

设置后 CSTP/DTLS 都不会打印 `batch record layer ENABLED`，`pd1_hw_fifo.enq` 不增长；这条已实机确认。

## 已知限制

- ZXSEC 批量记录层在 **OpenSSL 与 GnuTLS 两个后端**都生效；GnuTLS 分支依赖本仓库打了密钥钩子的 `libgnutls`。
- DTLS 只接管 **DTLS1.2 的 AES-GCM**；CSTP 接管 **TLS1.2 与 TLS1.3 的 AES-GCM**（TLS1.3 见下节）。AES-CBC 套件仍走原生 TLS 库。
- TLS1.3 特有限制：nonce 是 XOR 派生、AAD 只有记录头、真实类型在密文内部，这些已由记录层的 1.3 分支处理；但 **KeyUpdate / post-handshake auth 不支持**——读方向解出 inner handshake 记录（0x16）会按连接错误断线重连，ocserv 默认不会主动发 KeyUpdate，长连接下基本不触发。
- CSTP 写方向受服务端限制：一条 TLS 记录只能装一个 CSTP 帧，所以批量体现为“多条记录
  一次 `SUBMIT_BATCH`”，无法像 DTLS 那样把多包并成一条大记录；上行每帧仍是一条 ~1.4KB
  的记录，比 DOWN 方向的 ~1KB 记录条数更多，绝对 CPU 也略高。
- 不支持 TLS 重协商：`HelloRequest` 之类的握手记录进不了记录层，遇到会按连接错误处理并重连（ocserv 默认不主动 renegotiate）。
- 驱动 `max_batch=16`，单批上限固定；更大的记录（MTU）比更多批次更有效。
- 依赖固件自带 `zx279133` 驱动与 `/dev/zx279133-sec`；没有该设备的固件不要选这个包。

## 升级版本时

版本是钉死的（补丁针对具体源码生成），升级 = 换源码 + 重放补丁 + 重新验证：

1. 先分清两种「更新」：只改本项目逻辑 → 动对应包的 `PKG_RELEASE`，不动 `PKG_VERSION`；
   升级上游源码 → 走完整流程。
2. 换官方基线（openssl 取 `openwrt/openwrt` 的 `package/libs/openssl`，另两个取
   `openwrt/packages` 的 `net/openconnect`、`libs/gnutls`），整目录替换后先提交为
   「官方基线」commit；
3. 改 `PKG_VERSION` / `PKG_HASH`，同步 `setup-feed.sh` 里的版本检查和 README 的版本描述；
4. 按新源码重放 **10 个本项目补丁**（openssl 160/170，gnutls 100/110，openconnect
   100–150）：`patch -p1 --dry-run` 逐个试打，失败 hunk 手工对齐后重新 `diff -u`。
   重点锚点：`Makefile.in` 的 `am_libopenconnect_la_OBJECTS` 与
   `libopenconnect_la-dtls.lo: dtls.c`、150 号在 `openssl.c: openconnect_openssl_connect()`
   的接管点、160 号在 `ssl/t1_enc.c: tls1_change_cipher_state()` 末尾、
   170 号在 `ssl/tls13_enc.c: tls13_change_cipher_state()` 的
   `ssl_set_new_record_layer()` 前、100/110 号在 `lib/constate.c` 的
   `_gnutls_set_keys()` / `_tls13_set_keys()` 末尾；
5. 只改 `Makefile.in`，绝不能同时改 `Makefile.am`（会触发 automake，SDK 里没有）；
6. 双后端编译 + 符号验证（`readelf -sW openconnect | grep -c zxsec_`）+ 实机
   A/B（`ZXSEC_DISABLE=1` 基线、30Mbps 定速），全部通过后再提交「我们的改动」commit；
   由于重写历史，推送用 `git push --force-with-lease`。
