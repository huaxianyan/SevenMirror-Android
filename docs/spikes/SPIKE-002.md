# SPIKE-002：通知图标、头像与正文图片占位

## 目标

验证 Android 10／API 29 起可以在不传输任意 Drawable、资源引用、外部 URL 或正文图片的前提下，为通知镜像生成有硬上限的应用图标和单张头像。

该 Spike 只处理 Android 本地规范化边界。媒体协议、逐接收方 E2EE 传递、Chrome 持久化和展示将在后续切片完成。在这些边界完成前，产品运行时仍只允许本应用创建的 synthetic 通知联网，第三方通知继续禁止。

## 当前规则

- 应用图标从来源 package 的 `PackageManager` 图标读取。
- 头像最多选择一张。Android 11／API 30 起优先使用最新 MessagingStyle 发送者图标；所有支持版本随后回退到通知 large icon 和 `EXTRA_PEOPLE_LIST` 中最后一个可用 Person 图标。API 29 不调用 API 30 才公开的 MessagingStyle bundle parser。
- Drawable 只渲染到新的 `ARGB_8888` Bitmap，不保留原始对象、资源 ID 或 URI。
- 输出统一为静态 PNG；不会启动 animated drawable，因此动图只保留当前静态帧。
- 保持宽高比，最长边不超过 `256 px`。
- PNG 超过 `128 KiB` 时按 3／4 逐级缩小，直到满足上限；无法渲染或编码时不生成媒体。
- 内容摘要为规范化 PNG exact bytes 的 SHA-256。
- BigPicture 或 MessagingStyle image data 只设置 `containsContentImage`，正文末尾追加一次固定 `[图片]`；不读取或上传正文图片本身。
- 图标或头像失败不改变标题、正文、revision、action 或通知生命周期。

## 安全边界

- 当前没有新增网络字段，Server 和 Chrome 不会收到这些媒体。
- 单个规范化媒体在进入协议前已经满足尺寸和字节上限。
- 规范化器捕获 Drawable 加载／绘制／分配失败并返回无媒体；文本通知仍可继续。
- 应用图标和头像的 byte array 目前只存在于 Android 进程内的 bounded notification snapshot。
- `[图片]` 是业务正文规范化结果，不是本地化 UI 文案，也不包含原图数据。

## 验证

Android instrumentation 覆盖：

1. `1024×512` Drawable 规范化为 `256×128` bounded PNG，并验证 PNG signature 与 exact SHA-256；
2. 绘制时抛出异常的 Drawable 返回无媒体；
3. BigPicture 正文只追加 `[图片]`，同时应用图标和 large-icon 头像仍满足上限。

## 后续切片

1. 在 Server 权威 protobuf 中定义 bounded media message，并更新 canonical spec／向量；
2. Android 只把规范化结果写入每 recipient 的 notification plaintext，再经现有 Auth HPKE 加密；
3. Chrome 在 canonical validation 后持久化媒体，使用 `chrome.notifications` 支持的单一 `iconUrl` 展示头像优先、应用图标回退；
4. 验证 Server 日志和 SQLite 无媒体明文，并执行 synthetic 真实端到端验收；
5. 上述链路完成前不放行第三方通知。
