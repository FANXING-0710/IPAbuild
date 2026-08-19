# IPAbuild

利用 GitHub Actions 免费 macOS runner（public 仓库）构建并回传 iOS IPA 的小仓库。

## 构建目标

- **IOGPUProbe** — M5 iPad (iOS 26.6) IOGPUDeviceUserClient 内核读写路径探针 app。
  两个按钮：
  - A. 连接扫描（service × type 0-9）+ sel0/sel2 可达性测试
  - B. 竞态测试（高风险，可能触发内核 panic 导致设备重启）

## 用法

1. 修改 `IOGPUProbe/main.m`
2. push 到 main（或手动触发 workflow）
3. GitHub Actions 自动用 macOS runner 编译成 `IOGPUProbe.ipa`
4. IPA 通过两种方式获取：
   - 仓库 `dist/IOGPUProbe.ipa`（自动回传提交）
   - Actions → Artifacts `IOGPUProbe-ipa`
5. SideStore / LiveContainer 安装测试

结果日志写入 app 的 `Documents/IOGPU_result.log`。
