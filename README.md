# ⚠️ Please Use Ommega / 请使用 Ommega

> [!IMPORTANT]
> **English:** The concept envisioned by this project has now been fully realized by [Ommega](https://github.com/jiyin004-jpg/ommega). Ommega provides complete local keychain forwarding for spoofed-BL-unlocked devices and jailbroken devices, and has successfully achieved Google Play Integrity `STRONG_INTEGRITY`. Please use Ommega instead.
>
> **中文：** 本项目所预期实现的构想现已由 [Ommega](https://github.com/jiyin004-jpg/ommega) 完整落地。Ommega 可完整转发伪 BL 解锁设备和越狱设备的本地密钥链，并已成功达到 Google Play Integrity `STRONG_INTEGRITY` 等级。请大家直接使用 Ommega。

---

# TEESimulator-RS-Online

**Remote attestation relay for Android devices** — forward hardware key attestation from a BL-locked device (Provider) to a BL-unlocked device (Consumer) over WebSocket.

基于 [TEESimulator-RS](https://github.com/Enginex0/TEESimulator-RS) 的远程证书链转发方案。将 BL 锁定设备（Provider）的真实硬件 attestation 通过 WebSocket 中继到 BL 解锁设备（Consumer），实现 6 段 Google 硬件认证链。

---

## Architecture / 架构

```
┌─────────────────┐         WebSocket + PSK         ┌─────────────────┐
│   Device A      │◄──────────────────────────────►│   Device B      │
│   (Consumer)    │                                 │   (Provider)    │
│   BL Unlocked   │         ┌───────────┐          │   BL Locked     │
│   KSU + Module  │◄───────►│  VPS Relay │◄────────►│   Provider APK  │
│                 │         │  (Rust)    │          │   Real TEE      │
└─────────────────┘         └───────────┘          └─────────────────┘
```

**EN**: Device A intercepts `generateKey` calls via binder hook. When attestation is needed, it sends the public key + challenge to Device B through the relay server. Device B uses its real TEE to sign the attestation, producing a valid 6-cert chain rooted at Google Hardware Attestation Root. The chain is returned to Device A and injected into the keystore response.

**中文**: 设备 A 通过 binder hook 拦截 `generateKey` 调用。需要 attestation 时，将公钥 + challenge 经中继服务器发送给设备 B。设备 B 使用真实 TEE 签发 attestation，产生以 Google 硬件认证根证书为根的 6 段有效证书链，返回给设备 A 注入 keystore 响应。

---

## Project Goal / 项目目标

The end goal is to let a **BL-unlocked Consumer** pass Google Play Integrity
STRONG_INTEGRITY by leveraging a **BL-locked Provider**'s real TEE.

Path so far:

1. **v1.0** (released): forward the attestation chain. Passes local
   verifiers but not Play Integrity.
2. **v2.0** (in design): forward the entire keystore session. Targets Play
   Integrity. See [protocol-v2-rfc.md](OmegaRelay/docs/protocol-v2-rfc.md).

最终目标：利用 **BL 锁定** 的 Provider 真实 TEE，让 **BL 解锁** 的 Consumer 通过
Google Play Integrity STRONG_INTEGRITY。

路线：
1. **v1.0**（已发布）：转发证书链。通过本地验证器但无法过 Play Integrity。
2. **v2.0**（设计中）：转发整个 keystore 会话。目标是 Play Integrity。
   详见 [protocol-v2-rfc.zh.md](OmegaRelay/docs/protocol-v2-rfc.zh.md)。

---

## Components / 组件

| Directory | Description |
|---|---|
| `app/` | TEESimulator-RS with OmegaRelay Consumer integration (KSU/Magisk module) |
| `OmegaRelay/server/` | Rust WebSocket relay server |
| `OmegaRelay/android/` | Provider APK (runs on Device B) |
| `OmegaRelay/protocol/` | Shared protocol library (Rust, msgpack) |
| `OmegaRelay/vps/` | One-click VPS deployment script |
| `OmegaRelay/module/provider/` | KSU module packaging for Provider |

---

## Quick Start / 快速开始

### 1. Deploy Relay Server / 部署中继服务器

```bash
# On your VPS (Debian/Ubuntu/RHEL):
sudo OMEGA_PSK="$(openssl rand -hex 32)" \
     OMEGA_DOMAIN=relay.example.com \
     bash OmegaRelay/vps/install.sh
```

Or without TLS (put behind nginx):
```bash
sudo OMEGA_PSK="your-secret-key" OMEGA_NO_TLS=1 bash OmegaRelay/vps/install.sh
```

### 2. Setup Provider (Device B) / 配置 Provider（设备 B）

Download `OmegaRelay-Provider-v1.0.0-signed.apk` from [Releases](https://github.com/Andrea-lyz/TEESimulator-RS-Online/releases) and install on a **BL-locked** device.

Provider device requirements / Provider 设备要求：

- **For v1.0 (current)**: BL-locked + valid TEE + valid keybox available.
- **For v2.0 (in design, targets Play Integrity)**: BL-locked + RKP support
  (Android 12+) + KSU jailbreak mode (Magica + SELinux permissive trick) so
  the device retains root while TEE still reports `verifiedBootState=Verified`.
  See [Holy Grail thread on XDA](https://xdaforums.com/t/the-holy-grail-universal-no-bl-root-for-qualcomm-devices-bypass-locked-bootloaders.4782827/) for the jailbreak procedure.

从 [Releases](https://github.com/Andrea-lyz/TEESimulator-RS-Online/releases) 下载 `OmegaRelay-Provider-v1.0.0-signed.apk`，安装到 **BL 锁定**的设备上。

Provider 设备要求：

- **v1.0（当前）**：BL 锁定 + 有效 TEE + 可用 keybox。
- **v2.0（设计中，目标 Play Integrity）**：BL 锁定 + RKP 支持（Android 12+） +
  KSU 越狱模式（Magica + SELinux 宽容模式技巧），设备保持 root 的同时 TEE 仍
  报告 `verifiedBootState=Verified`。越狱流程参考
  [XDA Holy Grail 帖](https://xdaforums.com/t/the-holy-grail-universal-no-bl-root-for-qualcomm-devices-bypass-locked-bootloaders.4782827/)。

Open the app and configure:
- URL: `ws://your-vps-ip:8443/` or `wss://relay.example.com:8443/`
- PSK: (same as server)
- Device ID: `device-b-1`

The app supports both `ws://` (cleartext) and `wss://` (TLS) to any address — no IP whitelist needed.

应用支持 `ws://`（明文）和 `wss://`（TLS）连接任意地址，无需 IP 白名单。

### 3. Setup Consumer (Device A) / 配置 Consumer（设备 A）

Download `TEESimulator-RS-v6.0.0-165-Release.zip` from [Releases](https://github.com/Andrea-lyz/TEESimulator-RS-Online/releases).

从 [Releases](https://github.com/Andrea-lyz/TEESimulator-RS-Online/releases) 下载 `TEESimulator-RS-v6.0.0-165-Release.zip`。

Flash via KSU/Magisk/APatch on Device A (BL unlocked):
```bash
# KSU example:
adb push TEESimulator-RS-v6.0.0-165-Release.zip /data/local/tmp/
adb shell "su -c 'ksud module install /data/local/tmp/TEESimulator-RS-v6.0.0-165-Release.zip'"
adb reboot
```

After reboot, edit the relay config:
```bash
adb shell "su -c 'vi /data/adb/modules/tricky_store/omega-relay.conf'"
```

```ini
url = ws://your-vps-ip:8443/
psk = your-secret-key
device_id = device-a-1
```

Reboot again for the config to take effect:
```bash
adb reboot
```

重启后编辑中继配置文件，填入你的 VPS 地址、PSK 和设备 ID。**修改配置后需要再次重启**才能生效。

### 4. Verify / 验证

Use [Key Attestation](https://github.com/nicholaschum/KeyAttestation) app on Device A:
- Should show "Google Hardware Attestation Root Certificate" / 应显示"Google 硬件认证根证书"
- Chain length: 6 / 链长度：6
- End-to-end latency: 200-500ms / 端到端延迟：200-500ms

Check relay logs on Device A:
```bash
adb logcat -s TEESimulator:V | grep -i relay
```

---

## Debugging & Troubleshooting / 调试与排障

### View Consumer logs / 查看 Consumer 日志

```bash
# All TEESimulator logs (verbose)
adb logcat -s TEESimulator:V

# Only relay-related logs
adb logcat -s TEESimulator:V | grep -iE "relay|RELAY|task|chain"

# Clear logcat and start fresh
adb logcat -c && adb logcat -s TEESimulator:V
```

### View Provider logs / 查看 Provider 日志

```bash
# Provider APK logs
adb logcat -s OmegaRelay:V

# Or filter by package
adb logcat --pid=$(adb shell pidof org.ommega.relay.provider.app)
```

### View VPS server logs / 查看 VPS 服务器日志

```bash
# Live logs
journalctl -u omega-relay -f

# Last 100 lines
journalctl -u omega-relay -n 100 --no-pager

# Restart server
sudo systemctl restart omega-relay
```

### Force reconnect relay (Consumer) / 强制重连中继（Consumer 端）

The relay client lives inside the `keystore2` process. To force reconnect:

中继客户端运行在 `keystore2` 进程内。强制重连方法：

```bash
# Method 1: Kill keystore2 (system will auto-restart it, module re-injects)
adb shell "su -c 'killall keystore2'"

# Method 2: Full reboot (most reliable)
adb reboot
```

### Force reconnect relay (Provider) / 强制重连中继（Provider 端）

```bash
# Restart the Provider app service
adb shell "su -c 'am force-stop org.ommega.relay.provider.app'"
# Then reopen the app, or it will auto-restart via BootReceiver on next boot
```

### Check relay connection status / 检查中继连接状态

```bash
# Consumer side: look for "authenticated" or "connected"
adb logcat -d -s TEESimulator:V | grep -iE "authenticated|connected|disconnect"

# Provider side:
adb logcat -d -s OmegaRelay:V | grep -iE "authenticated|connected|disconnect"

# VPS side: check active connections
journalctl -u omega-relay --since "5 min ago" | grep -i "hello\|disconnect"
```

### Test attestation manually / 手动测试 attestation

```bash
# Trigger a key attestation and watch the relay in action
adb logcat -c
# Open Key Attestation app on Device A, tap "Attest"
adb logcat -s TEESimulator:V | grep -iE "relay|task|chain|OK"
```

Expected output / 期望输出:
```
RelayEngine: task <uuid> OK in <N>ms, chain len=6
RELAY: installed remote chain (len=6) over placeholder for <alias>
```

### Common issues / 常见问题

| Symptom / 现象 | Cause / 原因 | Fix / 解决 |
|---|---|---|
| `RelayEngine: connect failed` | Wrong URL/PSK or server down | Check config, `curl ws://ip:8443/` from PC |
| `RelayEngine: task timeout` | Provider offline or sleeping | Wake Device B, check Provider app is running |
| `RELAY: no provider available` | Provider not connected to server | Check Provider logs, restart Provider app |
| `chain len=0` | Provider TEE refused to sign | Check Device B is BL-locked, keybox present |
| No relay logs at all | Config not loaded | Verify `omega-relay.conf` exists and reboot |

| 无任何 relay 日志 | 配置未加载 | 确认 `omega-relay.conf` 存在并重启 |
| 连接失败 | URL/PSK 错误或服务器宕机 | 检查配置，从电脑 `curl ws://ip:8443/` 测试 |
| 任务超时 | Provider 离线或休眠 | 唤醒设备 B，确认 Provider 应用在运行 |
| 无 Provider 可用 | Provider 未连接服务器 | 检查 Provider 日志，重启 Provider 应用 |
| chain len=0 | Provider TEE 拒绝签名 | 确认设备 B BL 锁定，keybox 存在 |

---

## Building / 构建

### Prerequisites / 前置条件

- Android SDK (API 36)
- NDK 27.3+
- Rust toolchain + `cargo-ndk`
- JDK 21

### Build Consumer Module / 构建 Consumer 模块

```powershell
# Windows (paths with non-ASCII need these env vars):
$env:CARGO_TARGET_DIR = "C:\Temp\teesim-rust-target"
.\gradlew.bat :app:zipRelease
# Output: out/TEESimulator-RS-*.zip
```

### Build Relay Server / 构建中继服务器

```bash
cd OmegaRelay
cargo build --release -p omega-server
# Binary: target/release/omega-server
```

### Build Provider APK / 构建 Provider APK

```bash
cd OmegaRelay/android
./gradlew :daemon-provider-app:assembleRelease
```

---

## Protocol / 协议

See [OmegaRelay/docs/protocol.md](OmegaRelay/docs/protocol.md) for the full protocol specification.

协议详情见 [OmegaRelay/docs/protocol.md](OmegaRelay/docs/protocol.md)。

---

## Security Notes / 安全说明

- All communication is authenticated via PSK (pre-shared key)
- TLS is strongly recommended for production deployments
- The relay server never sees private keys — it only forwards opaque attestation tasks
- Provider device must remain BL-locked for valid attestation

- 所有通信通过 PSK（预共享密钥）认证
- 生产环境强烈建议启用 TLS
- 中继服务器不接触私钥——仅转发不透明的 attestation 任务
- Provider 设备必须保持 BL 锁定才能产生有效 attestation

---

## Limitations / 限制

### v1.0 (current release / 当前发布版本)

**v1.0 cannot pass Google Play Integrity**. The bottleneck is not the
attestation chain — Provider B's chain is real and rooted at Google. The
problem is that GMS DroidGuard performs **multiple keystore operations** on
the same alias (generateKey → sign → sign → ...), but the private key in
v1.0 lives only on Provider B. Consumer A cannot satisfy the subsequent
`sign` calls.

v1.0 **does** pass: vvb2060 KeyAttestation, Duck Detector (Tamper score ≤ 8),
and any local X.509 chain verification.

**v1.0 无法通过 Google Play Integrity**。瓶颈不在证书链——Provider B 签出来的链
是真实的、根证书是 Google 的。问题在于 GMS DroidGuard 会对同一个 alias 执行**多
次 keystore 操作**（generateKey → sign → sign → ...），而 v1.0 中私钥只存在于
Provider B 上，Consumer A 无法响应后续的 `sign` 调用。

v1.0 **能通过**：vvb2060 KeyAttestation、Duck Detector（Tamper score ≤ 8）、
以及任何本地 X.509 链验证。

### v2.0 (in design / 设计中)

v2.0 is being designed to forward the **entire keystore session** (not just
the attestation step). This means every `sign` operation on Consumer A is
routed through the relay to Provider B's TEE, with the private key never
leaving B. Combined with KSU jailbreak mode on Provider B (real
`verifiedBootState=Verified`), this should allow Consumer A to pass Play
Integrity STRONG_INTEGRITY.

See [protocol-v2-rfc.md](OmegaRelay/docs/protocol-v2-rfc.md) for the full
design draft.

v2.0 正在设计中，目标是转发**整个 keystore 会话**（不只是 attestation 步骤）。
Consumer A 上的每次 `sign` 操作都会通过中继路由到 Provider B 的 TEE，私钥从不
离开 B。配合 Provider B 上的 KSU 越狱模式（真实的
`verifiedBootState=Verified`），理论上可以让 Consumer A 通过 Play Integrity
STRONG_INTEGRITY。

完整设计详见 [protocol-v2-rfc.zh.md](OmegaRelay/docs/protocol-v2-rfc.zh.md)。

---

## Duck Detector Fix / Duck Detector 修复

This fork includes a fix for the "TEE Simulator generate-mode fingerprint" detection:

Changed `SecurityLevel.SOFTWARE` → `SecurityLevel.KEYSTORE` in `createSwAuth()` to match real hardware behavior. See [OMEGA_INTEGRATION.md](OMEGA_INTEGRATION.md) for details.

本 fork 包含对 "TEE Simulator generate-mode fingerprint" 检测的修复：将 `createSwAuth()` 中的 `SecurityLevel.SOFTWARE` 改为 `SecurityLevel.KEYSTORE` 以匹配真实硬件行为。

---

## Credits / 致谢

- [TEESimulator-RS](https://github.com/Enginex0/TEESimulator-RS) by JingMatrix & Enginex0
- [LSPlt](https://github.com/LSPosed/LSPlt) for native hooking
- Protocol inspired by [Ommega](https://github.com/nicholaschum/ommega)

---

## License / 许可证

GPLv3. See [LICENSE](LICENSE).
