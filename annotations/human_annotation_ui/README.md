# 本地人工标注界面

该界面读取冻结的 150 条源码上下文，并把结果直接、原子地保存到现有
`annotations/annotator/annotator_a.jsonl` 或 `annotator_b.jsonl`。它不会展示
五模型投票，不会执行仓库代码，也不会把数据上传到网络。

## 发给多名参与者（推荐）

双击仓库根目录的 `开始多人标注.cmd`，输入用空格分隔的参与者编号，例如：

```text
reviewer01 reviewer02 reviewer03
```

启动器会输出每个人独立且带随机邀请令牌的链接。只把对应链接发给对应
参与者；对方打开浏览器即可标注，不需要安装仓库、Python 或阅读额外说明。
远程链接把令牌放在 `#invite=` URL fragment 中，避免令牌进入代理 URL 日志。
保持启动窗口开启，结果会实时保存到：

```text
annotations/annotator/participants/annotator_reviewer01.jsonl
annotations/annotator/participants/annotator_reviewer02.jsonl
annotations/annotator/participants/annotator_reviewer03.jsonl
```

重新用相同参与者编号启动会复用原邀请链接和保存进度。邀请令牌存放在
被 Git 忽略的 `annotations/annotator/invitations.local.json`，不要提交或公开。
参与者需要能访问你的电脑：同一局域网最直接；跨网络时应使用组织批准的
VPN/Tailscale 类私网，不要直接把端口暴露到公网。

双击根目录的 `查看标注进度.cmd` 可以查看每位参与者的完成数量和最后保存
时间，不会显示或合并他们的具体标签。

## 启动标注者 A

```powershell
python scripts\serve_human_annotation.py --annotator A
```

## 启动标注者 B

应由另一名人员独立完成，且不能查看 A 的结果：

```powershell
python scripts\serve_human_annotation.py --annotator B --port 8766
```

浏览器会自动打开本地地址。关闭终端或按 `Ctrl+C` 停止服务；已保存的结果
不会丢失。界面支持保存草稿、完成校验、进度筛选和快捷键：

- `Ctrl+S`：保存草稿
- `Ctrl+Enter`：完成当前任务并跳到下一条未完成任务

## 标注原则

1. 黄色行只是扫描器证据，不代表漏洞。
2. 危险能力本身不等于弱点或漏洞。
3. 同一文件出现输入与效果不等于存在依赖。
4. 证据不足时使用“不确定”“未知”“部分成立”或“未评估”。
5. 理由必须引用源码行号。
6. 两名标注者冻结结果前，不得查看彼此结果或模型分歧队列。
