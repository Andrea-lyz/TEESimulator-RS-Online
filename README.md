<p align="center">
  <h1 align="center">TEESimulator-RS</h1>
  <p align="center"><b>Full TEE Emulation for Rooted Android</b></p>
  <p align="center">
    <a href="https://github.com/Enginex0/TEESimulator-RS/actions/workflows/build.yml"><img src="https://github.com/Enginex0/TEESimulator-RS/actions/workflows/build.yml/badge.svg" alt="Build"></a>
    <img src="https://img.shields.io/badge/Android-10%2B-green?logo=android" alt="Android 10+">
    <a href="https://t.me/superpowers9"><img src="https://img.shields.io/badge/Telegram-community-blue?logo=telegram" alt="Telegram"></a>
  </p>
</p>

---

> [!NOTE]
> Fork of [JingMatrix/TEESimulator](https://github.com/JingMatrix/TEESimulator) with native Rust certificate generation, key persistence, and AOSP-compliant attestation behavior. For the upstream project, see the original repo.

## What It Does

TEESimulator intercepts Binder IPC at the `ioctl` level inside the `keystore2` process and generates entire certificate chains from scratch, signed by your keybox, with correct attestation extensions. Apps that verify hardware attestation see a legitimate device.

This is not TrickyStore. TEESimulator replaces TrickyStore and its forks entirely. It shares the same config paths for drop-in compatibility, but the internals are different: native Rust cert generation, binder-level interception via `lsplt`, per-UID rate limiting, key persistence, and AOSP-spec attestation behavior.

## Requirements

> [!IMPORTANT]
> A valid `keybox.xml` is required for hardware-level attestation. Without one, the module generates software-level certificates that won't pass strict hardware checks.

1. Android 10+
2. Root manager: KernelSU, Magisk, or APatch
3. `keybox.xml` at `/data/adb/tricky_store/keybox.xml`

## Quick Start

1. Download the latest ZIP from [Releases](https://github.com/Enginex0/TEESimulator-RS/releases)
2. Install via your root manager and reboot
3. Place your keybox at `/data/adb/tricky_store/keybox.xml`
4. Configure targets in `/data/adb/tricky_store/target.txt`
5. Verify with Play Integrity or Key Attestation Demo

## Architecture

**Native Cert Generation** — `libcertgen.so` generates X.509 chains in Rust using `ring` and manual DER encoding. BouncyCastle fallback for unsupported curves (P-224, P-521, Curve25519).

**Binder Interception** — PLT hook on `ioctl()` in `libc.so` via `lsplt` inside `keystore2`. Intercepts `generateKey`, `importKey`, and `getKeyEntry` transactions.

**AOSP Compliance** — Self-signed certs for non-attested keys (matching `ta/src/keys.rs`), correct AuthorizationList tag ordering, version-guarded extension fields, `authorize_create` enforcement.

**Key Persistence** — Generated keys survive reboots. File-backed with file-level locking.

**Rate Limiting** — Per-UID hardware keygen cap (2/30s window, 2 concurrent). Overflow falls to software certs.

## Configuration

All config files live at `/data/adb/tricky_store/` and are hot-reloaded via `FileObserver`.

### target.txt

Controls which apps get intercepted and the simulation mode.

| Suffix | Mode |
|--------|------|
| `!` | Force software key generation |
| `?` | Force leaf certificate patching (real TEE key, patched cert) |
| *(none)* | Automatic selection |

Multi-keybox support via `[filename.xml]` headers:

```
com.google.android.gms!
io.github.vvb2060.keyattestation?

[aosp_keybox.xml]
com.google.android.gsf
```

### security_patch.txt

Override patch levels reported in attestation certificates. Global defaults at top, per-package overrides with `[package.name]`.

| Key | Scope |
|-----|-------|
| `system` | OS patch level |
| `vendor` | Vendor patch level |
| `boot` | Boot/kernel patch level |
| `all` | Sets all three |

Special values: `today`, `YYYY-MM-DD` templates, `no` (omit tag), `device_default`, `prop` (read from system property).

```
system=YYYY-MM-05
vendor=device_default
boot=no

[com.google.android.gms]
system=2025-10-01
```

### boot_props_mode

Controls global `ro.boot.*` property spoofing. Values: `auto` (default), `force`, or `disable`.

In `auto`, Oplus-family devices (OnePlus/OPPO/realme/Oplus) skip boot-state prop spoofing to avoid conflicts with vendor TEE services such as ultrasonic fingerprint calibration. Create `/data/adb/tricky_store/boot_props_mode` with `force` to restore the old behavior, or `disable` to turn it off on any device.

## Building from Source

Prerequisites: JDK 21, Android SDK/NDK 27, Rust stable with `aarch64-linux-android` target, `cargo-ndk`.

```bash
git clone --recursive https://github.com/Enginex0/TEESimulator-RS.git
cd TEESimulator-RS
./gradlew zipRelease zipDebug
```

Output ZIPs in `out/`. Gradle invokes `cargo ndk` automatically to cross-compile `libcertgen.so`.

Push to `main` or use **Actions > Build > Run workflow** to trigger CI.

## Compatibility

| Root Manager | Status |
|---|---|
| KernelSU | Tested (Action button + lifecycle scripts) |
| Magisk | Supported |
| APatch | Supported |

## Community

<p align="center">
  <a href="https://t.me/superpowers9">
    <img src="https://img.shields.io/badge/SuperPowers_Telegram-Join-blue?style=for-the-badge&logo=telegram" alt="Telegram">
  </a>
</p>

## Credits

- [JingMatrix](https://github.com/JingMatrix/TEESimulator) — original TEESimulator and interception architecture
- [5ec1cff](https://github.com/5ec1cff/TrickyStore) — TrickyStore, the project that pioneered keystore interception
- [LSPlt](https://github.com/LSPosed/LSPlt) — PLT hook library
- [ring](https://github.com/briansmith/ring) — Rust cryptography library
- [MhmRdd](https://github.com/MhmRdd) — AOSP compliance work via upstream [PR #157](https://github.com/JingMatrix/TEESimulator/pull/157)
- [fatalcoder524](https://github.com/fatalcoder524) — contributor and collaborator
- [huguangares](https://github.com/huguangares) — collaborator and tester

## License

[GNU General Public License v3.0](LICENSE)
