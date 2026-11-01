# 法隐 LegalRedactor

中文法律文书本地脱敏工具。纯本地、零成本、不吃 GPU。

核心不是"识别得多准"，而是**脱敏到底干不干净**：真删除（不是画黑框）、
跨文件一致化（同一个人不会一会儿叫张某一会儿叫李某）、
以及**脱敏后把产物当敌意输入反向攻击一遍**的残留自检。

想直接验证质量：`pip install -r requirements.txt && python tests/test_units.py && python tests/e2e.py`（样本是合成数据，脚本自动生成）。

设计思路与威胁模型见 [docs/DESIGN.md](docs/DESIGN.md)。
参考项目是 [DataInfra-RedactionEverything](https://github.com/ttttccxxui/DataInfra-RedactionEverything)
（原名 TracyWang95/legal-redaction），借鉴了它的 Schema 驱动 + 行业预设 +
文本/视觉双链路 + 人工复核的骨架，但把 vLLM+HaS+LocateAnything+PaddleOCR
那套 16GB 显存的重型推理栈换成了规则 + 词典 + OpenCV + RapidOCR(ONNX/CPU)，
8GB 显存的笔记本也能跑，实际推理不吃 GPU。

---

## 快速开始

需要 Python 3.10+。装依赖：

```bash
pip install -r requirements.txt
```

OCR（`rapidocr-onnxruntime`）与 PyMuPDF 是可选的——不装也能跑，
工具会自动跳过对应链路并在报告里说明，不会静默出残缺产物。

先自检依赖与资源是否齐备：

```bash
python -m legal_redactor doctor
```

`doctor` 会逐项列出缺失组件及其影响，并把实际解析到的预设目录、
复核界面路径、可写工作目录打印出来。

### 1. 只扫描，不改动

```bash
python -m legal_redactor scan tests/samples/民事判决书.docx
python -m legal_redactor scan 卷宗/ --preset legal_public --all --json 检出.json
```

### 2. 脱敏 + 残留自检

```bash
python -m legal_redactor redact 民事判决书.docx 询问笔录.docx \
    -o 交付/ \
    --preset legal \
    --mapping-pass '你的口令' \
    --zip-pass '打包口令'
```

产物：

```
交付/
  民事判决书.脱敏.docx
  询问笔录.脱敏.docx
  脱敏对照表.enc.json          AES 加密，需要 --mapping-pass 的口令才能打开
  脱敏交付包.zip               AES-256 加密（pyzipper），只含产物与审计报告
  audit/
    民事判决书.脱敏.audit.html  可直接打开看的自检报告
    民事判决书.脱敏.audit.md
    民事判决书.脱敏.audit.json
```

**自检不通过时进程返回码为 2**，可以直接挂 CI 或批处理里当门禁。

### 3. 整目录批量

```bash
python -m legal_redactor batch 卷宗目录/ -o 交付/ --preset legal --mapping-pass '口令'
```

跨文件一致化：先扫全部文件、把实体登记进同一个解析器、
用第一遍确认过的姓名回喂检测器再扫一遍，最后统一写盘。
所以 A 文件里出现的当事人，在 B 文件里也会被认出来并替换成同一个假名。

遇到 `.doc` / `.xls` / `.ppt` / `.rtf` 会明确拒绝并说明原因，不会假装能处理。

### 4. 本地复核界面

```bash
python -m legal_redactor serve --port 8765
```

浏览器打开 `http://127.0.0.1:8765`。只监听回环，页面不引任何外部资源，断网可用。

能做的事：拖入文件或从本机目录选取 → 扫描 → 正文里高亮看每一处检出 →
点开看依据/置信度/识别路径 → 逐条采纳或忽略、单条改策略 → 视觉区域（印章/二维码/OCR）逐个开关 →
脱敏并自检 → 界面内直接看审计结论、下载产物与报告。

低置信度项（<0.75）默认标成"建议人工确认"。这是设计，不是缺陷：
纯规则方案的姓名召回有上限，与其偷偷漏掉，不如把它摆到你面前让你点一下。

### 5. 解密对照表

```bash
python -m legal_redactor mapping 交付/脱敏对照表.enc.json --pass
```

---

## 支持的格式

| 格式 | 处理方式 | 覆盖范围 |
|---|---|---|
| `.docx` | OOXML zip 手术 + 段落级文本投影 | 正文、表格、文本框、页眉、页脚、脚注、尾注、批注、修订历史、文档属性、自定义属性、内嵌图片、嵌入的 docx/xlsx（递归）、缩略图 |
| `.pdf`（文本版） | PyMuPDF 字符级投影 + 真 redaction | 文本层删除、图像像素擦除、注释弹窗、嵌入文件、`/Info` 与 XMP 元数据 |
| `.pdf`（扫描版） | 渲染 → OpenCV/RapidOCR → 坐标换算回 PDF 空间 | 印章、二维码、OCR 出的敏感文字 |
| `.txt` `.md` `.csv` `.log` `.json` `.yaml` `.xml` | 编码嗅探 + 偏移替换 | 全文，输出统一 UTF-8 |
| `.xlsx` `.xlsm` | openpyxl 另存 | 单元格、公式、批注、定义名称、数据验证列表、页眉页脚、文档属性 |
| `.png` `.jpg` `.bmp` `.tif` `.webp` | OpenCV 检测 + 实心覆盖 + 重编码 | 红章（含骑缝章）、二维码、OCR 文字、EXIF（含 GPS）剥离 |

**明确不支持**：`.doc` `.xls` `.ppt`（老式二进制，黑底覆盖后原文仍在二进制流里）、
`.rtf`、`.odt`、`.pptx`、音视频。工具会拒绝并说明原因。

---

## 预设

`schemas/*.yaml`，可复制改名自定义。

| 预设 | 用途 |
|---|---|
| `legal` | 默认。脱自然人身份与联系方式，保留案号/法院名/法人名称/金额/日期。未成年人信息强制脱敏 |
| `legal_public` | 裁判文书上网版。追加：审判员书记员姓名、法定代表人、金额泛化、住址截到区县级、出生日期只留年份 |
| `litigation_internal` | 卷宗内部共享。只脱证件号与联系方式，保留姓名与地址 |
| `general` | 与行业无关的常规 PII |

```bash
python -m legal_redactor schema list          # 列预设
python -m legal_redactor schema show legal     # 看某个预设的完整动作表
python -m legal_redactor schema types          # 看实体类型注册表
```

临时改选项不用改 YAML：

```bash
python -m legal_redactor redact a.docx -o out/ -O address_level=4 -O person_mask_mode=pseudo -O pdf_style=box
```

---

## 策略

每种实体类型可独立指定，同一实体在全批次内保证映射一致。

| 策略 | 例 |
|---|---|
| `KEEP` | 原样保留 |
| `MASK` | 张伟民→张某某；北京市恒信律师事务所→北某某律师事务所（保留类型后缀，读者仍知道"这是间律所"） |
| `MASK_FULL` | →`[已脱敏]`，或 `-O mask_shape=block` 出等长 `■■■` |
| `PARTIAL` | 13801234567→138\*\*\*\*4567；11010519870312451X→110105\*\*\*\*\*\*\*\*451X |
| `PSEUDO` | 一致化假名，按 seed 确定性生成，且不撞文中真实姓名 |
| `CODE` | 当事人A / 单位1 / 地址2 |
| `GENERALIZE` | 地址截到区县级、日期截到年、金额落数量级区间、身份证只留省级码 |
| `DATE_SHIFT` | 全体日期平移 N 天，相对间隔不变 |
| `DELETE` | 整段移除 |
| `HASH` | HMAC 假名，跨库可关联但不暴露原值 |

`--seed` 相同则跨批次结果可复现。

---

## 残留自检

这是这个工具真正的交付物。产物会被当成敌意输入反向攻击一遍：

1. **全量再提取**——DOCX/XLSX 遍历 zip 里每个部件，XML 按 UTF-8 读、
   二进制按 UTF-8/UTF-16LE/Latin-1 三种编码都抠一遍；PDF 抽文本层 + 扫原始字节
   （增量更新历史里的旧对象只能这么发现）+ 每页栅格化后 OCR；图片直接 OCR。
2. **多粒度匹配**——全值、归一化值（全半角/空格/分隔符）、滑窗子串、
   结构残留（身份证出生日期段与顺序码、手机中间 4 位、银行卡 BIN 与后 4 位、
   姓名去姓、邮箱 local part、地址门牌段）。
3. **巧合排除**——6 位滑窗在长数字里撞车概率很高，命中片段所在的极大字母数字串
   若不是原值的子串，判为巧合而非残留。
4. **元数据**——DOCX 的 `docProps/*`、PDF 的 `/Info` 与 XMP、XLSX 属性、图片 EXIF（GPS 单独按致命处理）。
5. **修订与批注**——产物里是否还有 `w:ins` / `w:del` / `w:delText` / `w:moveFrom` / `w:comment` / 批注作者名。
6. **视觉复检**——产物图片/页面再跑一次红章、二维码、OCR。
7. **替换落地**——产物里能不能找到替换值。找不到说明"检测到了但没写进去"。
   扫描件与图片没有文本层，这一项自动改成"像素已改写 + 视觉复检干净"。
8. **组合重识别提示**——产物里还剩几类准标识符（年份/行政区划/性别/民族/金额/社会属性）。
   单个不敏感，组合起来可能足以定位到人。工具只提示，不替你决策。

严重级 `critical`/`high` 任意一条即判 **FAIL**，进程返回码 2。

---

## 实测结果

样本是脚本生成的、贴近真实形态的中文法律文书（`tests/make_samples.py`），
**刻意把敏感信息埋进了页眉、页脚、批注、修订历史、文档属性、缩略图和内嵌红章图**——
这些都是"正文改了就以为完事"的工具会漏的地方。
所有证件号/银行卡号都通过真实校验位（GB 11643、GB 32100、Luhn），
保证检测器走的是完整判定路径而不是碰巧匹配。

`python tests/e2e.py` 六种格式全通过：

| 样本 | 检出 | ground-truth 召回 | 替换 | 自检 |
|---|---:|---:|---:|:--:|
| `当事人清单.txt` | 97 span | 37/37 = 100% | 76 | ✅ PASS |
| `民事判决书.docx` | 98 span + 5 视觉区域 | 37/37 = 100% | 75 | ✅ PASS |
| `当事人信息表.xlsx` | 24 span | 20/20 = 100% | 21 | ✅ PASS |
| `签章页.png` | 5 视觉区域 | 4/5（印章环绕文字 OCR 读不出，但章已整体涂掉） | 3 | ✅ PASS |
| `民事判决书_文本版.pdf` | 148 span + 38 视觉区域 | 37/37 = 100% | 115 | ✅ PASS |
| `民事判决书_扫描版.pdf` | 20 视觉区域 + 32 OCR span | 9/16（OCR 精度上限，不作门槛） | 26 | ✅ PASS |

图片与扫描件不设召回门槛——那是 OCR 的精度上限，不是脱敏的成败判据。
它们的门槛是"产物里 OCR 不出任何敏感信息、印章与二维码已涂除"。

`python tests/test_units.py` **34/34** 通过（校验位、中文数字与日期往返、地址级别截断、
姓名结构判定、span 归并/裁剪/区域标记保留、保留类不得压制脱敏类、遮盖与部分保留形态、
泛化、日期平移保持相对间隔、HMAC 稳定性、一致化与假名不撞真名、强制升级、
对照表加解密、审计片段与巧合排除、列头驱动检测、人工放行与工具失误分离）。

### 第三方独立验证

自己的审计说自己干净不算数。`scripts/verify_with_word.ps1` 用本机**真实 Word**
（COM 自动化）打开脱敏产物，走一条和工具内部完全不同的提取路径。实测结果：

| 验证项 | 结果 |
|---|---|
| 不触发"文件已损坏/需要修复" | ✅ OOXML 结构合法，Word 正常打开 |
| 全部 StoryRange（正文/页眉/页脚）搜 40 个原始敏感值 | ✅ **命中 0** |
| 反向核对 5 项有意保留内容（信用代码/法人名/两个法院名/案号） | ✅ **5/5 仍在**，没脱过头 |
| 修订数 / 批注数 | ✅ 0 / 0 |
| Author / LastSaveBy / Title / Subject / Keywords / Comments / Category | ✅ 全空 |
| 导出 PDF | ✅ 成功 |

```bash
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/verify_with_word.ps1
```

这条验证在开发中抓到过**工具自身审计报 0 残留、实际却漏了**的两处（见下），
所以它不是走过场。

两个脚本细节值得一提：
- Word 的 `Range.Find.Execute()` 会把 Range 移到命中处，复用同一个 Range 连搜几十个词
  会让后续搜索从上次位置往后找，产生大面积假阴性。改成对每个 StoryRange 取一次
  `.Text` 快照做字符串包含判定。踩过了。
- 搜索列表必须区分"必须消失"和"按预设有意保留"，否则会把正确的保留行为报成丢失。

### 验证过程中真实抓到的两个漏洞

1. **`docProps/thumbnail.jpeg`（L11）**——Word 的首页缩略图是位图快照，
   页眉页脚里的当事人姓名和电话都在里面。工具自身的 zip 文本审计按 latin-1 硬抠字节，
   在缩略图里撞出了手机号后 4 位才暴露出这个部件。现在直接删部件 + 删关系 + 删 Override。
2. **保留类实体吃掉脱敏类实体（L12）**——页眉"（2023）京0102民初18765号　**张伟民**诉
   北京华远置业有限公司"里，ORG 检测器向前回溯把"张伟民诉"一起吃进机构名，
   而机构名在 legal 预设下是保留的，于是姓名被整个吞掉且不做任何替换。
   **工具自身的审计当时报 0 残留**——因为那个地址从未被检出、也就从未进对照表，审计无从核对。
   是 Word COM 这条独立路径抓出来的。修复方式不是补一个停止词，而是加了一条通用原则：
   **保留类实体永远不能压制脱敏类实体**（`merge_spans` 的 `deprioritize`），
   并配了回归测试。同一个 bug 还连带导致住所地地址不脱敏、出生日期不做泛化、开户行原样保留。

### 人工放行 vs 工具失误

复核时明确标"忽略"的项，产物里会保留原值，自检会搜到它。
这种残留**不计入通过/不通过判定**，但会单列成「人工放行清单」写进报告
（类型、原值、位置、放行依据）。

法律场景下"谁决定保留的、保留了什么"和"脱干净了没有"同样重要，
所以既不把它算成工具失败让 FAIL 变成噪声，也不允许它被静默吞掉。

---

## 目录结构

```
fayin_main.py         打包入口（必须是顶层脚本，见"打包成 exe"一节）
build_exe.py          PyInstaller 构建脚本
legal_redactor/
  resources.py        资源路径解析：源码态与冻结态一致
  core.py             实体类型注册表、Span/Box、预设、策略枚举
  detect/
    base.py           检测器接口、span 归并与冲突消解、归一化
    lexicon.py        姓氏（含高风险姓黑名单）、法律角色词、地址/机构词典、通用词表
    regex_det.py      强标识符 + GB11643/GB32100/Luhn 校验位
    name_det.py       姓名四路径：角色触发 / 落款 / 姓氏词典 / 跨文档学习
    addr_det.py       地址锚点+吞噬+级别回溯、开户行
    org_det.py        法院 / 律所 / 机构
    legal_det.py      案号 / 金额 / 日期 / 出生日期 / 未成年人区域 / 医疗
    vision_det.py     cv2 红章（含骑缝章）+ 二维码 + RapidOCR
    pipeline.py       编排、姓名两遍学习、区域升级、列头驱动、后校验
  strategies/
    replacer.py       10 种策略、中文数字、日期解析与重写
    resolver.py       全局实体解析与一致化、假名生成
    mapping.py        对照表导出、PBKDF2+Fernet 加密
  formats/
    docx_fmt.py       OOXML 手术：修订接受、文本投影、元数据、缩略图、嵌入对象
    pdf_fmt.py        字符级投影、真 redaction、栅格化兜底
    text_fmt.py       编码嗅探
    xlsx_fmt.py       单元格/公式/批注/定义名称/页眉页脚/属性
    image_fmt.py      实心覆盖 + EXIF 剥离
  engine.py           总编排、跨文件一致化批量
  audit.py            残留自检与报告
  cli.py              typer CLI
  server.py           stdlib http.server 复核台
web/index.html        复核界面（单文件，无外部依赖）
schemas/*.yaml        行业预设
tests/
  make_samples.py     生成样本（含 ground truth）
  test_units.py       单元测试 31 项
  e2e.py              端到端 + 召回统计 + 审计门禁
  smoke_detect.py     检测冒烟
scripts/
  verify_with_word.ps1  真实 Word COM 独立验证
docs/DESIGN.md        设计说明与威胁模型
verify-out/           验证产物（独立目录）
```

---

## 依赖

见 `requirements.txt`。全部是纯本地开源库，**不需要 GPU、不需要联网、
不需要任何云端 API key**，代码里没有任何远程调用。

缺失时的降级行为由 `doctor` 命令逐项列出，不会静默跳过。

**许可注意**：PyMuPDF 是 AGPL-3.0。自用无碍；若要对外分发，
PDF 走 `formats/pdf_fmt.py` 里的 `PdfRasterFallback`（pypdfium2，Apache-2.0/BSD），
代价是产物没有文本层、不可搜索。

---

## 已知局限

写在明处，不装。

1. **姓名召回有上限。** 纯规则+词典对生僻姓、无角色词上下文的名字会漏。
   三层缓解：低置信项摆到复核界面让人点；跨文档学习把确认过的名字回喂全文；
   审计的去姓片段检查能抓到部分漏网。做不到"闭眼全自动零漏"，
   任何声称做到的纯规则方案都在吹。
2. **准标识符组合重识别无法自动判定。** 工具能泛化单个字段，但
   "1987年生 + 某村 + 独子 + 教师"这种组合是否可重识别需要人判断。
   审计报告给"高风险组合提示"，不替你决策。
3. **印章环绕文字 OCR 读不出来。** 弧形排布的字 RapidOCR 识别率低。
   实测样本里"北京华远置业有限公司"这枚章的文字没被 OCR 读到——
   但整枚章被 cv2 检出并涂掉了，所以不构成泄露，只是对照表里少一条记录。
4. **扫描件召回受 OCR 精度限制。** 实测 9/16。低分辨率、手写体、模糊件会更差。
5. **PDF 里以绘图指令而非文本层存在的文字**（矢量图、流程图）扫不到。
   兜底是整页栅格化，代价是不可搜索。
6. **EMF/WMF 矢量图**（Word 里常见）cv2 无法栅格化处理，工具会明确告警，
   建议先在 Word 里转成位图再跑。
7. **XLSX 经 openpyxl 另存会丢掉公式的缓存计算值**，需要 Excel 重算。
8. **不处理音视频。**

---

## 打包成 exe

```bash
python build_exe.py            # onedir + 便携 zip（默认，推荐）
python build_exe.py --onefile  # 单文件
python build_exe.py --no-zip   # 只构建
```

产物在 `dist/`：

| | |
|---|---|
| `dist/FaYin/FaYin.exe` | 15.4 MB（真正的逻辑在 `_internal/`） |
| `dist/FaYin/` | 303 MB，607 个文件 |
| `dist/FaYin-0.1.0-win64.zip` | 135.6 MB，便携分发包 |

分发包里除了程序还有三个**双击即用**的启动器：

- `启动复核台.bat` — 起服务并开浏览器
- `依赖与资源自检.bat` — 跑 `doctor`
- `把文件拖到这里脱敏.bat` — 把文件拖到它图标上，产物进同目录的 `脱敏产物/`

以及 `schemas/` 四个预设的**可编辑副本**——改预设不必重新打包。

用法与命令行完全一致：

```
FaYin.exe redact 判决书.docx -o 交付 --preset legal --mapping-pass 口令
FaYin.exe serve
FaYin.exe doctor
```

### 为什么默认 onedir 而不是 onefile

两个本机实测的硬约束：

1. onefile 每次启动要把约 250MB（cv2 82MB + pymupdf 25MB + onnxruntime 28MB +
   numpy openblas 20MB + OCR 模型 16MB…）解到 `%TEMP%`，而 `%TEMP%` 在 **C 盘，
   当前已用 94%、只剩 14GB**。
2. 解压让冷启动多花好几秒，对反复跑的批处理很难受。

onedir 启动即用、便于排查、杀软误报也更少。要单文件就加 `--onefile`，
脚本会先把这个代价打印出来。

### 打包踩过的三个坑（都已修，写在这里免得下次重犯）

1. **入口不能指向包内的 `cli.py`**。PyInstaller 会把它当顶层脚本执行，
   没有父包上下文，`from .core import ...` 直接
   `ImportError: attempted relative import with no known parent package`。
   **而且构建日志照样打印 "Build complete!"**——必须真跑一次 exe 才暴露。
   正确做法是根目录顶层脚本 `fayin_main.py` 去 `from legal_redactor.cli import main`。
2. **资源路径必须走 `legal_redactor/resources.py`**。冻结态下
   `Path(__file__).parents[1]` 不是项目根（源码树根本不存在），
   `schemas/*.yaml` 和 `web/index.html` 会全部找不到。
   `resources.py` 统一解析 `sys._MEIPASS`，并在 exe 同级优先读用户可编辑的 `schemas/`。
   `doctor` 会把实际解析到的路径打印出来，一眼能看出打包漏没漏 `--add-data`。
3. **冻结态控制台码页是 936(GBK)**。rich 在 legacy Windows 渲染路径上用该码页编码输出，
   遇到 `✓ ✗ ✅ ┌` 直接 `UnicodeEncodeError` 把整条命令炸掉。
   `fayin_main.py` 启动时 `SetConsoleOutputCP(65001)` + `reconfigure(errors="replace")` 双重兜底。

另外 `pyzipper` 的 AES 后端 `Cryptodome` 是在 `zipfile_aes.py` 里延迟导入的，
PyInstaller 静态分析看不到——构建能过、exe 能跑，**直到第一次用 `--zip-pass` 才炸**。
已在 `build_exe.py` 里显式声明 `CRYPTODOME_HIDDEN`。这类"只在某个分支缺"的模块必须写死。

### exe 实测（与源码版同一套验收）

| 验证项 | 结果 |
|---|---|
| `doctor` 资源解析 | ✅ `_internal` 根、4 个预设、index.html 存在、可写目录正确 |
| txt / docx / xlsx / png / pdf 五格式脱敏 | ✅ 76 / 75 / 21 / 3 / 115 处替换，自检**全 PASS，0 残留** |
| DOCX 修订历史与批注 | ✅ 无 `w:ins`/`w:del`/批注残留 |
| 对照表加密 | ✅ 54 条，明文里查不到任何原值；正确口令可解、错口令被拒 |
| AES-256 交付包 | ✅ 生成成功、错口令被拒；默认只装产物不装审计报告 |
| `serve` 复核台 | ✅ health 显示 cv2/OCR/PyMuPDF/pypdfium2 全部可用；session→pick→scan→redact 全通过 |
| **真实 Word 验证 exe 的产物** | ✅ 不触发修复对话框、40 个敏感值命中 0、5 项有意保留的 5/5 仍在、修订 0 批注 0、导出 PDF 成功 |

---

## 许可

MIT。第三方组件（尤其 **PyMuPDF 是 AGPL-3.0**）的授权义务由分发构建包的你自行承担，
详见 [`LICENSE`](LICENSE) 末尾的组件清单与规避路径。

---

## 一个使用提醒

对照表就是还原钥匙。`--mapping-pass` 给了口令它才进交付目录（AES 加密）；
不给口令则明文写到 `report/` 下，**不在交付目录里**。
别把它和产物一起发出去，否则等于没脱敏。
