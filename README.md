# SevenMirror Android

SevenMirror 的发送端：在本机捕获通知，端到端加密后只发给你自己的浏览器。三个独立仓库之一。

仓库地址：<https://github.com/huaxianyan/SevenMirror-Android>

> 状态：本机通知操作、认证 HPKE、重放与幂等恢复、严格注册、可恢复的 Keystore 封装传输凭据轮换，以及认证后的 WebSocket 传输均已验证。应用把用户的显式应用选择绑到加密的通知新增、移除、快照与远程操作上，能自己发现半死的中继 socket 而不再往里排队，并在认证后主动发起 `SNH1`／`SNH2` 心跳。它会在 `BOOT_COMPLETED` 后自行启动前台服务，因此重启设备不再需要手动打开应用。厂商 ROM 兼容性、通知权限兜底路径与首个正式版的产品验收仍未完成。

## 这是什么

SevenMirror 把 Android 通知显示到桌面浏览器上。本应用是唯一的来源：浏览器不申请桌面通知权限，离开手机的是发给单个收件人的密文。通知正文与 `PendingIntent` 能力只留在进程内存里。

两个权限决定一切。通知使用权让应用看到系统投递了什么。通知权限决定前台服务能否存活，而前台服务决定中继连接能否存活，所以撤销通知权限就会停止镜像，直到首页出现待处理的权限入口。电池优化豁免是前台服务丢失前台状态时的兜底，不强制要求，也不影响耗电。

使用步骤：

1. 从 GitHub Releases 安装 APK，或自行从源码构建（见下文）。
2. 打开应用，走完首次引导，其中包括「后台同步」这一步的决定。
3. 用中继运维者签发的一次性加入码加入私有空间。
4. 选择要镜像哪些应用。持续显示的通知默认不镜像。
5. 显示名由中继运维者设定，应用只读展示。

socket 失败后应用自行重连。设备重启并解锁后，不需要打开应用就能恢复连接。

## 环境要求

- JDK 17
- Android SDK 37，即 `compileSdk`，`targetSdk` 为 35
- Android Studio，或仓库自带的 Gradle wrapper
- 最低运行版本：Android 10 / API 29

## 构建

```sh
./gradlew verifyKotlinKaptAdvisoryGuard verifyVendoredProtocol test lint assembleDebug
```

Windows 的 PowerShell 或命令提示符下改用 `gradlew.bat`。

## 依赖完整性

所有可解析的构建、运行时、单元测试、仪器测试与 Kotlin 编译器插件配置都启用 Gradle 严格依赖锁定。AGP 合成的 `*DependenciesMetadata` 配置被排除，因为 AGP 9.4／Gradle 9.6 不为它们提供可持久化的锁定状态，而它们与真实 classpath 上的依赖重复。

要有意升级依赖版本，执行：

```sh
./gradlew \
  :app:dependencies \
  :core-crypto:dependencies \
  :core-notification:dependencies \
  :core-protocol:dependencies \
  :core-transport:dependencies \
  writeReleaseRuntimeDependencyInventory \
  --write-locks
./gradlew verifyKotlinKaptAdvisoryGuard verifyVendoredProtocol test lint assembleDebug \
  --write-verification-metadata sha256
```

提交前逐条复核每个锁文件，以及 `gradle/verification-metadata.xml` 里新增的产物校验和。不要改用宽松校验，也不要在 CI 里生成校验和。CI 会校验清单稳定性，并拒绝任何不在已入库 SHA-256 元数据里的产物。按 SHA 固定的 OSV Scanner v2.5.1 会阻断精确发布运行时清单中的已知漏洞。另有一条供应链审计扫描 `verification-metadata.xml` 里的完整产物与 Gradle／插件清单。已知的上游 Android 构建工具问题仍会显示在那里，但不会被冒充成 APK 运行时依赖。剩余的 Kotlin Gradle 插件告警记录与「无 KAPT」这条被强制的可达性边界，见 [`docs/kotlin-kapt-advisory-analysis.md`](docs/kotlin-kapt-advisory-analysis.md)。

## 开发与 CI 流程

每个功能分支的 push 都会跑 CI。该分支的精确 SHA 必须先通过必需的 `build` 与 `api29-secure-runtime` 检查，才能快进到 `main`。产出的 `main` SHA 要通过同样的检查，主题分支才会被删除。API 29 模拟器只在构建与依赖完整性任务成功后才启动。这些顺序规则减少重复的 runner 失败，不放松任何构建、OSV、仪器测试或发布门禁。

名为 `connected*AndroidTest` 的 Gradle 任务依赖 `verifyConnectedTestsUseEmulators`。该守卫会在 instrumentation 开始前拒绝任何已连接的真机，因为 Android Gradle Plugin 的 connected 任务可能卸载目标应用并清除其私有数据。这类任务只允许在一次性模拟器上运行。真机上的产品验收走安装已签名的 release／debug APK 并执行明确的用户流程，不用 Gradle 的 connected 测试任务。

## 本地敏感数据

API 29 的仪器测试套件使用真实的 Android Keystore 后端存储与 canary 凭据。它逐个检查 SharedPreferences、数据库、应用文件、缓存、本进程 logcat 与生成的错误信息，确认其中没有原始或编码过的传输凭据，也没有 HPKE 私钥标量。预期的端侧协议状态，以及操作系统、备份、崩溃、截图与业务内容方面仍未覆盖的边界，见 [`docs/SENSITIVE_DATA.md`](docs/SENSITIVE_DATA.md)。

## 签名

可分发的 debug 与 release APK 使用项目固定的 Android 签名身份，以便后续构建保持覆盖安装兼容。本地密钥文件已被 Git 忽略，GitHub Actions 从仓库 secret 重建 keystore 并校验证书指纹。固定的签名身份、备份边界、CI secret 名称与恢复规则见 [`docs/SIGNING.md`](docs/SIGNING.md)。已签名 APK 的 provenance、离线校验、分发渠道信任与 `versionCode` 单调回滚规则见 [`docs/release-provenance.md`](docs/release-provenance.md)，被固定的发布 Action 见 [`docs/release-actions.md`](docs/release-actions.md)。

## 模块

- `app`：Material 3 Compose 首次引导。底部栏与导航栏自适应布局，宽屏内容宽度有上限。应用选择可搜索，能区分普通应用与系统应用，且是显式保存的。持续通知默认排除，另有全局静默通知开关与逐应用的内容、持续通知设置。前台服务由用户可控、优先级低，承载持续的加密中继连接，并在设备重启后由开机接收器恢复。电池优化豁免作为可选兜底提供。远程操作权限可全局也可逐应用设置。设备展示是经权威验证的只读视图。另有面向用户的连接恢复与隐私／设置界面、应用私有的传输诊断环形文件，以及仅调试版可用的合成夹具入口。前台服务边界见 [`docs/background-connection.md`](docs/background-connection.md)，环形文件见 [`docs/transport-diagnostics.md`](docs/transport-diagnostics.md)
- `core-notification`：接入 `NotificationListenerService`，对用户可见更新去重。确定性选取 200 项活跃集，并对分组摘要去重。另提供已批准发送者的操作分发，以及本地执行前强制校验的来源应用远程操作授权
- `core-protocol`：协议模型与生成代码位置
- `core-crypto`：认证 HPKE，重放与操作账本，不可变的已批准对端固定。它负责工作区名册的权威、证书与名册校验，也提供权威签名的只读设备目录与持久回滚下限。另有执行前的结果预留、持久发件箱与序号分配，以及有界加密结果排空
- `core-transport`：严格的加入码注册。它实现 ADR-005 名册 register／prove／state 的 HTTP 客户端，并在 Keystore 里封装待处理入网日志与传输凭据，支持可恢复的证明与轮换状态。还有经权威验证、可恢复的名册到传输提升，以及传输凭据加载前的进程启动入网恢复。传输层是 Device Auth Frame v1 与认证的 OkHttp WebSocket 边界，带基于 ping 的半死 socket 检测与 `SNH1`／`SNH2` 发起。另有每 60 秒一次、保证「状态非 `ONLINE` 时必有排定重连」的巡检
- `notification-fixture`：仅供开发使用的第三方应用，用于受控的通知生命周期、操作、回复、分组、状态与媒体验收。它有独立的应用 ID，不依赖 SevenMirror 任何模块，也不进入发布产物

## 协议

服务端仓库是协议的权威来源。本仓库在 `protocol/` 下 vendor 一份固定副本：`protocol/UPSTREAM_REF` 记录上游提交，`protocol/PROTOCOL_VERSION` 记录这些资产发布所用的版本，每个资产旁有一个 `*_SHA256` 文件钉住它的确切字节。副本一旦漂移，`verifyVendoredProtocol` 会让构建失败。当前 schema 为 `0.1.0`，仍是暂定版。在协议 v1 冻结之前，版本号不构成兼容性承诺。

## 安全状态

调试版可以信任设备用户显式安装的 CA，以便用私有开发 PKI 在真机上验证非回环的 HTTPS／WSS。该例外通过 Android 网络安全配置的 `debug-overrides` 表达。不可调试的 release 版本不信任用户添加的 CA，仍要求系统信任的服务器证书。明文流量在既有的显式回环域之外仍被拒绝。

传输凭据轮换 v1 把当前凭据与至多一个待处理凭据存为两份独立的 Android Keystore AES-GCM 密文，绑定同一套服务器、工作区、设备与 HPKE 身份元数据。`prepared` 与 `attempted` 会在严格不跟随重定向的 HTTPS 请求之前提交。HTTP 200 不会提升凭据。进程死亡或响应丢失后，已尝试的待处理凭据会精确重试。`SNO1` 之前的拒绝回落到当前凭据，只有待处理凭据收到 `SNO1` 才允许原子重封装与提升。原始凭据不出现在 SharedPreferences，载入的工作副本会被清除。

中继投递 v1 把所选应用的通知新增、移除、重连快照与认证的操作结果信封包装为显式的持久提交。收到确切的 `SNO1` 之后，Android 从自己确切的工作区与设备游标恢复。入站的持久帧只有在操作与结果确认对账落盘之后，才推进并累积确认。快照要求的高水位会被持久化，且从不自动跳过。快照请求与响应恢复对经权威授权的接收端开启。

监听器只把通知正文与 `PendingIntent` 能力留在进程内存里。未被选中的应用的通知只为本地监听记账保留，永不进入镜像出口。保存更改后的选择会分配新的 revision，按需发出新增或移除，随后跟一道新的活跃集快照屏障。远程操作、回复与清除还需要在最终副作用边界上通过既有的、默认关闭的逐应用授权。socket 失败使用 1 到 60 秒的带抖动指数退避。持久的凭据或身份失败保持 `SECURITY_ERROR`，不按网络失败重试。本机处理中的失败会放弃连接并排定重连，而不是把设备停住。只有三条判定「对端自己的字节」的入站路径会停住设备，另有一个每 60 秒的检查，在有连接持有者却不处于 `ONLINE` 时重新武装连接。全局拒绝明文传输，只有显式的回环开发域例外。

有两条边界值得单独说明。远程清除只在通知是持续通知时被拒绝，因为系统的 `NotificationManagerService` 在监听器取消单条通知时只检查 `FLAG_ONGOING_EVENT`。浏览器会把这个拒绝报出来，而不是默默等待。应用私有的诊断环形文件只记录传输状态与时序，从不记录通知正文、凭据或身份。release 构建也会写它，因为事实证明只靠 logcat 无法事后重建一次连接中断。

## 发布

发布由 `release-artifacts.yml` 在推送形如 `v<versionName>` 的标签时触发，标签必须与 [`release/release-identity.properties`](release/release-identity.properties) 里的 `versionName` 一致，带 `-dev` 的版本不允许按标签发布。工作流先构建并用固定签名身份签署 release APK，校验其公开身份，再生成 GitHub provenance。随后 `publish-release` 任务创建 GitHub Release，资产为 APK、`release-manifest.json` 与 `SHA256SUMS`。

发布页正文由 `docs/release-notes/<标签>.md` 加上自动生成的「构建信息」表拼成，标题只写标签本身。正文保持简短，使用方式、验收证据与构建范围属于仓库内的长期文档。`scripts/verify_release_notes.py` 在 CI 里强制这一形态。

## 许可证

当前修订版使用 [`GPL-3.0-only`](LICENSE)。允许商业使用，但分发时必须遵守 GPLv3。此前已经发布的 MIT 版本不受追溯影响，精确的 MIT 到 GPL 边界见 [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md)，该边界修订及其祖先仍按 MIT 提供。
