# SevenMirror Android

把手机上的通知送到你自己的浏览器。本应用是发送端，负责在本机捕获通知、按收件人加密，再发给你指定的浏览器。三个独立仓库之一。

仓库地址：<https://github.com/huaxianyan/SevenMirror-Android>

> 状态：日常使用已经可用。通知镜像、远程操作与回复、接收浏览器选择、暂停与恢复、开机自启都已实现。厂商 ROM 兼容性与第二台不同品牌真机的验证尚未完成。

## 能做什么

- **把通知发到浏览器**：只发送你在手机上选中的应用。离开手机的正文已经加密，中继服务器读不到内容。
- **在电脑上处理通知**：可以直接标记完成、发送回复，或清除这条通知。
- **自己决定发给谁**：在「设置 → 接收设备」里勾选接收通知的浏览器。不勾选就不发送。
- **暂停与恢复**：不想被打扰时暂停同步。恢复后自动对账，补上当前状态。
- **逐应用控制**：每个应用都可以单独决定是否镜像、是否显示正文、是否允许远程操作。
- **持续通知单独开关**：常驻式通知默认不镜像，需要时可以按应用打开。
- **后台保持连接**：退出应用或锁屏后连接仍然保持，新通知即时送达。
- **重启后自动恢复**：重启手机并解锁后连接自行恢复，不需要手动打开应用。
- **掉线自己重连**：网络抖动导致的断开会自动退避重连，界面不会跳到需要重新注册的页面。
- **隐私默认收紧**：通知正文与点击能力只留在内存里，远程操作默认关闭，需要时逐应用开启。

## 怎么用

SevenMirror 是自托管项目，你需要先有一台运行中继服务的服务器。服务器可以自己搭建，搭建方式见服务端仓库。

1. 安装应用。可以从本仓库的 Releases 下载 APK，也可以自行构建。
2. 打开应用，走完首次引导。其中会问你是否开启后台同步。
3. 输入运维者签发的一次性加入码，加入你的私有空间。
4. 选择要镜像哪些应用。
5. 在「设置 → 接收设备」里勾选接收通知的浏览器。

设备显示名由运维者在管理端设定，应用里只读展示。

## 运行要求

- Android 10（API 29）或更高版本
- 一个已经搭好的 SevenMirror 中继服务
- 手机上的通知使用权，以及通知权限

## 自行构建

需要 JDK 17、Android SDK 37（`compileSdk` 为 37，`targetSdk` 为 35），以及 Android Studio 或仓库自带的 Gradle wrapper。

```sh
./gradlew verifyKotlinKaptAdvisoryGuard verifyVendoredProtocol test lint assembleDebug
```

Windows 的 PowerShell 或命令提示符下改用 `gradlew.bat`。

## 发布

推送形如 `v0.1.0` 的标签即触发发布。标签必须与 `release/release-identity.properties` 里的 `versionName` 一致，带 `-dev` 的版本不能按标签发布。

工作流用固定的签名身份构建并签署 release APK，校验它的公开身份，再生成 GitHub provenance。发布页正文来自 `docs/release-notes/<标签>.md`，标题只写标签本身。完整规则见 [发布溯源](docs/release-provenance.md)。

## 更多文档

面向开发与运维的细节拆到独立文档，不放在这里。

| 主题 | 文档 |
| --- | --- |
| 界面结构、业务边界与已知待办 | [产品界面](docs/product-interface.md) |
| 后台连接、前台服务与重连策略 | [后台连接](docs/background-connection.md) |
| 传输诊断与故障排查 | [传输时间线](docs/transport-diagnostics.md) |
| 本地敏感数据清单与审计 | [敏感数据](docs/SENSITIVE_DATA.md) |
| 签名身份、备份与恢复 | [签名](docs/SIGNING.md) |
| 发布产物、离线校验与回滚 | [发布溯源](docs/release-provenance.md) |
| 发布流程用到的 Action 与权限 | [发布 Action](docs/release-actions.md) |
| 依赖清单与漏洞证据 | [漏洞证据](docs/vulnerability-evidence.md) |
| Kotlin 插件告警与无 KAPT 边界 | [KAPT 分析](docs/kotlin-kapt-advisory-analysis.md) |
| 协议资产、版本与校验方式 | [协议资产](protocol/README.md) |

## 许可证

当前修订版使用 [`GPL-3.0-only`](LICENSE)。允许商业使用，但分发时必须遵守 GPLv3。此前已经发布的 MIT 版本不受追溯影响，精确的 MIT 到 GPL 边界见 [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md)，该边界修订及其祖先仍按 MIT 提供。
