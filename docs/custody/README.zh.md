# docs/custody/ — 你的个人信任记录

> 这个文件夹装着 **只有你能创建的 6 个文件**。它们是 YOYO 的公开信任记录。填好这些、用 GPG 签名、推送到 GitHub，YOYO 就"因你的签名而可信"。

## 你的身份

- **名字**: [你的名字]
- **邮箱**: [你的邮箱]
- **GPG 密钥 ID**: [待你生成 GPG 后填入密钥 ID]

## 这 6 个文件

| # | 文件 | 用途 | 创建时间 |
|---|------|------|----------|
| 1 | `01-audit-yoyo-js.md` | 你对 162 行种子编译器的审计 | 30 分钟 |
| 2 | `02-audit-isa.md` | 你对 38 指令 ISA 表的审计 | 30 分钟 |
| 3 | `03-GOLDEN_HASH.txt` | yoyo.js 的 SHA-256，你 pin 的信任根 | 1 分钟 |
| 4 | `04-SELF_HOST_VERIFIED.md` | 签收 M0≡M1≡M2≡M3 自举链 | 5 分钟 |
| 5 | `05-DDC_VERIFIED.md` | 签收 DDC 验证（JS ≡ Rust）| 5 分钟 |
| 6 | `06-FROZEN.md` | 签收冻结编译器 | 5 分钟 |

**总时间**：~1.5 小时专注工作。

## 中文版（私人）

为你自己参考，中文版放在同文件夹里，带 `.zh.md` 或 `.zh.txt` 后缀：

- `README.zh.md` — 中文版本 README
- `01-audit-yoyo-js.zh.md` — 中文审计模板
- `02-audit-isa.zh.md` — 中文 ISA 审计模板
- `03-GOLDEN_HASH.zh.txt` — 中文 golden hash 模板
- `04-SELF_HOST_VERIFIED.zh.md` — 中文自举模板
- `05-DDC_VERIFIED.zh.md` — 中文 DDC 模板
- `06-FROZEN.zh.md` — 中文冻结模板

**中文版被 .gitignore 屏蔽** —— 不会推送到 GitHub。只供你私人参考。

## 工作流程

```
1. 填好每个文件（把 [待你生成 GPG 后填入密钥 ID] 等占位符替换成你的真实数据）
2. 用 GPG 给每个 .md/.txt 签名
   $ gpg --default-key 你的密钥ID --sign --detach-sign 文件名
3. 提交 + GPG 签名 commit
   $ git add docs/custody/
   $ git commit -S -m "签署 YOYO 信任链"
4. 推送到 GitHub
   $ git push origin main
5. 在 GitHub 上确认每个 commit 显示"Verified"
```

## 为什么是特别文件夹？

这个文件夹**只属于你**。其他开发者、AI、承包商都不应写入。如果你在 Git 历史里看到不是你的 commit 在这个文件夹，**立即调查**。

文件夹结构在传递一个信号：**这是人类的信任记录，不是自动生成的代码**。

## 别人如何验证

```bash
# 1. 克隆仓库
$ git clone https://github.com/你的用户名/yoyo
$ cd yoyo

# 2. 导入你的公钥
$ gpg --import 你的公钥.asc

# 3. 验证每个签名
$ gpg --verify docs/custody/03-GOLDEN_HASH.txt.sig docs/custody/03-GOLDEN_HASH.txt
$ gpg --verify docs/custody/04-SELF_HOST_VERIFIED.md.sig docs/custody/04-SELF_HOST_VERIFIED.md
$ gpg --verify docs/custody/05-DDC_VERIFIED.md.sig docs/custody/05-DDC_VERIFIED.md
$ gpg --verify docs/custody/06-FROZEN.md.sig docs/custody/06-FROZEN.md

# 每个应该显示："Good signature from [你的名字] <[你的邮箱]>"
```

## 如果丢了 GPG 密钥

你不能再签名。必须：

1. 生成新 GPG 密钥
2. 用新密钥创建新的签收文件
3. 公布密钥轮换
4. 旧签名仍可验证（用旧公钥），但你不再控制那个密钥

**保管好你的 GPG 密钥。** 建议离线备份。

## 每个文件里有什么

每个文件是**带占位符的模板**。替换占位符：

- `[待你生成 GPG 后填入密钥 ID]` — 你的 GPG 密钥 ID（生成 GPG 后填入）
- `[M0 哈希]`、`[M1 哈希]` 等 — 实际的 SHA-256 哈希（签名时计算）
- `[你的笔记]`、`[你的推理]` — 审计时填写
- `[或者：列出严重问题]` — 替换为实际发现

## 操作顺序

文件之间有依赖关系：

```
01-audit-yoyo-js.md   ← 任何时候都可以做
02-audit-isa.md       ← 任何时候都可以做
03-GOLDEN_HASH.txt    ← 依赖 01（审计必须通过）
04-SELF_HOST_VERIFIED ← 依赖 02 + 自举验证
05-DDC_VERIFIED       ← 依赖 02 + DDC 验证
06-FROZEN             ← 依赖 03、04、05（必须全部签完）
```

**在所有都签名验证前不要冻结。**

## 空文件夹 = "还不被信任"

如果 `docs/custody/` 是空的或只有占位符文本，YOYO **还不被信任**。信任从你签 `06-FROZEN.md` 那一刻开始。

架构让 YOYO 变得可审计。**你的签名让 YOYO 变得可信。**

## 总结

| 步骤 | 动作 | 时间 |
|------|------|------|
| 1 | 填好 01-audit-yoyo-js.md | 30 分钟 |
| 2 | 填好 02-audit-isa.md | 30 分钟 |
| 3 | 跑自举验证，填好 03 + 04 | 10 分钟 |
| 4 | 跑 DDC 验证，填好 05 | 5 分钟 |
| 5 | 用 GPG 签 6 个文件 | 5 分钟 |
| 6 | 填好 06-FROZEN.md，签名 | 5 分钟 |
| 7 | 提交 + 推送到 GitHub | 5 分钟 |
| **总计** | — | **~1.5 小时** |

**第 7 步之后，YOYO 是可信的。你的签名让它成为现实。**
