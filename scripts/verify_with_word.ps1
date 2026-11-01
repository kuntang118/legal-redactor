# 用本机真实 Word 打开脱敏产物，验证三件事：
#   1) 不触发"文件已损坏/需要修复"——即 OOXML 结构合法
#   2) 用 Word 自己的对象模型（和我的 zip 刮取完全不同的路径）全文搜索原始敏感值，必须为 0
#   3) 能正常导出 PDF
# 输出统一写 UTF-8 文件，避开 GBK 控制台乱码。
param(
  [string]$Docx = "",
  [string]$Out  = ""
)

$ErrorActionPreference = "Stop"

# 默认路径相对脚本自身推导，不写死任何人的机器路径
$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Docx) {
  $Docx = Join-Path $RepoRoot "verify-out\e2e\民事判决书.脱敏.docx"
}
if (-not $Out) {
  $Out = Join-Path $RepoRoot "verify-out\word\word-verify.txt"
}
if (-not (Test-Path $Docx)) {
  Write-Error "找不到待验证的产物：$Docx`n请先跑 python tests/e2e.py 生成，或用 -Docx 指定一个脱敏后的 .docx"
  exit 2
}
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
$log = New-Object System.Collections.Generic.List[string]
function W($s) { $script:log.Add($s) }

# 必须消失的原始敏感值（ground truth + 刻意埋进页眉/页脚/批注/修订/属性的泄露点）
$sensitive = @(
  "张伟民","李建国","王志强","赵晓东","陈晓芸","孙丽华","刘振华","杨秀兰","郑国强","方文静",
  "11010519870312451X","310115199211058768","110108200905082214","440106197502281234",
  "13801234567","13911223344","13622223333","13711112222","13522223333",
  "zhangwm@example.com.cn","6222021123456787","11101201510123456",
  "粤A12345","粤BD12345","192.168.1.100","203.0.113.45","00:1A:2B:3C:4D:5E",
  "E12345678","C87654321","zhangwm1987",
  "010-66554433","13600001111",
  "北京市朝阳区建国路88号院3号楼2单元401室","上海市浦东新区世纪大道100号28层",
  "北京市海淀区中关村南大街5号","广东省广州市天河区体育西路103号",
  "北京市西城区金融大街7号英蓝国际金融中心12层","北京市东城区东直门南大街9号",
  "王承办法官","李书记员"
)

# 按 legal 预设**有意保留**的项：法人标识与公开信息，出现是正确的，不算残留
$keptByDesign = @(
  "91110102710931234J",                  # USCC 法人标识，公开可查
  "北京华远置业有限公司",                  # ORG 法人名称，裁判文书公开
  "北京市西城区人民法院",                  # COURT
  "北京市第二中级人民法院",                # COURT
  "（2023）京0102民初18765号"             # CASE_NO
)

$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0   # wdAlertsNone：损坏文件会弹修复框，这里让它静默并靠异常暴露
$opened = $false
try {
  W "=== Word COM 验证 ==="
  W "文件: $Docx"
  W "存在: $(Test-Path $Docx)  大小: $((Get-Item $Docx).Length) 字节"

  $doc = $word.Documents.Open($Docx, $false, $true)   # ConfirmConversions=false, ReadOnly=true
  $opened = $true
  W "打开: 成功（未触发修复对话框）"
  W "段落数: $($doc.Paragraphs.Count)"
  W "页数: $($doc.ComputeStatistics(2))"    # wdStatisticPages
  W "字数: $($doc.ComputeStatistics(0))"    # wdStatisticWords
  W "修订数: $($doc.Revisions.Count)"
  W "批注数: $($doc.Comments.Count)"

  # --- 全文（含页眉页脚、脚注、批注、文本框）搜索原始敏感值 ---
  # 不用 Range.Find：Execute() 会把 Range 移到命中处，复用同一个 Range 连续搜
  # 几十个词时，后面的搜索是从上一次的位置往后找的，会大面积假阴性
  # （实测把"北京市西城区人民法院"这种明明还在的内容报成"意外丢失"）。
  # 改成对每个 StoryRange 取一次 .Text 快照，用字符串包含判定。
  $storyTexts = @{}
  foreach ($st in $doc.StoryRanges) {
    $r = $st
    while ($r -ne $null) {
      $k = [int]$r.StoryType
      if ($storyTexts.ContainsKey($k)) { $storyTexts[$k] += "`n" + $r.Text }
      else { $storyTexts[$k] = $r.Text }
      $r = $r.NextStoryRange
    }
  }
  W "StoryRange 数量: $($storyTexts.Count)  类型: $(($storyTexts.Keys | Sort-Object) -join ',')"
  $allText = ($storyTexts.Values) -join "`n"
  W "Word 可见全文长度: $($allText.Length)"

  $hits = @()
  foreach ($v in $sensitive) {
    foreach ($k in $storyTexts.Keys) {
      if ($storyTexts[$k].Contains($v)) { $hits += "$v (story $k)"; break }
    }
  }
  W ""
  W "=== 敏感值搜索（Word 对象模型，独立于工具的 zip 刮取路径）==="
  W "待查项: $($sensitive.Count)"
  W "命中数: $($hits.Count)"
  if ($hits.Count -gt 0) { $hits | ForEach-Object { W "  ✗ 残留: $_" } }
  else { W "  ✓ 全部为 0，Word 里搜不到任何原始敏感值" }

  # 反向核对：按预设有意保留的项应该还在（否则说明脱敏过头，把公开信息也毁了）
  $kept = @()
  foreach ($v in $keptByDesign) {
    if ($allText.Contains($v)) { $kept += $v }
  }
  W ""
  W "=== 有意保留项核对（legal 预设：法人标识与公开信息不该被毁）==="
  W "应保留: $($keptByDesign.Count)  实际仍在: $($kept.Count)"
  $kept | ForEach-Object { W "  ✓ 保留: $_" }
  $lost = $keptByDesign | Where-Object { $kept -notcontains $_ }
  $lost | ForEach-Object { W "  ✗ 意外丢失: $_" }

  # 文档属性
  W ""
  W "=== 文档属性 ==="
  foreach ($p in @("Author","LastSaveBy","Title","Subject","Keywords","Comments","Category")) {
    $val = ""
    try { $val = $doc.BuiltInDocumentProperties.Item($p).Value } catch {}
    W ("  {0,-14} = '{1}'" -f $p, $val)
  }

  # 导出 PDF
  $pdf = [System.IO.Path]::ChangeExtension($Out, ".pdf")
  $doc.ExportAsFixedFormat($pdf, 17)   # wdExportFormatPDF
  W ""
  W "=== 导出 PDF ==="
  W "  成功: $pdf  大小: $((Get-Item $pdf).Length) 字节"

  # 抽样打印脱敏后的正文前 900 字，人工确认排版没崩
  W ""
  W "=== 脱敏后正文抽样（前 900 字）==="
  $body = $doc.StoryRanges.Item(1).Text   # wdStory
  W ($body.Substring(0, [Math]::Min(900, $body.Length)))

  $doc.Close($false)
} catch {
  W ""
  W "!!! 异常: $($_.Exception.GetType().Name): $($_.Exception.Message)"
  W $_.ScriptStackTrace
} finally {
  if ($opened) { try { $doc.Close($false) } catch {} }
  $word.Quit()
  [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

[System.IO.File]::WriteAllLines($Out, $log, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "written: $Out"
