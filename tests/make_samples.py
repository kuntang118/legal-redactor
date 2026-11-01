"""生成贴近真实的中文法律文书测试样本。

刻意覆盖最容易漏的泄露路径：
  L1 正文敏感值            L2 页眉/页脚          L3 修订历史(w:ins/w:del)
  L4 文档属性              L5 批注 comments.xml  L9 图片红章
  以及扫描版 PDF（无文本层）与文本版 PDF 两种形态
"""
from __future__ import annotations

import io
import shutil
import zipfile
from pathlib import Path

from lxml import etree

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "tests" / "samples"
SAMPLES.mkdir(parents=True, exist_ok=True)

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
CT = "http://schemas.openxmlformats.org/package/2006/content-types"
REL = "http://schemas.openxmlformats.org/package/2006/relationships"


def _w(t: str) -> str:
    return f"{{{W}}}{t}"


# --------------------------------------------------------------------------
# 判决书正文（所有证件号都通过校验位，能被真检测出来）
# --------------------------------------------------------------------------

JUDGMENT = """北京市西城区人民法院
民 事 判 决 书

（2023）京0102民初18765号

原告：张伟民，男，1987年3月12日出生，汉族，住北京市朝阳区建国路88号院3号楼2单元401室，公民身份号码11010519870312451X，联系电话13801234567，电子邮箱zhangwm@example.com.cn，微信号zhangwm1987。
委托诉讼代理人：李建国，北京市恒信律师事务所律师，执业证号11101201510123456，联系电话13911223344。

被告：北京华远置业有限公司，住所地北京市西城区金融大街7号英蓝国际金融中心12层，统一社会信用代码91110102710931234J，法定代表人王志强，职务董事长。
委托诉讼代理人：赵晓东，北京市恒信律师事务所律师，联系电话010-66554433转8021。

第三人：陈晓芸，女，1992年11月5日出生，汉族，住上海市浦东新区世纪大道100号28层，公民身份号码310115199211058768，联系电话+86 136 2222 3333。

原告张伟民与被告北京华远置业有限公司、第三人陈晓芸房屋买卖合同纠纷一案，本院于2023年6月15日立案后，依法适用普通程序，公开开庭进行了审理。原告张伟民及其委托诉讼代理人李建国、被告北京华远置业有限公司的委托诉讼代理人赵晓东、第三人陈晓芸到庭参加诉讼。本案现已审理终结。

原告张伟民向本院提出诉讼请求：1.判令被告返还购房定金人民币贰拾万元整（¥200000元）；2.判令被告支付违约金50000元；3.本案诉讼费用由被告承担。事实和理由：2023年4月1日，原告与被告签订《商品房认购书》，约定购买被告开发的位于北京市朝阳区建国路88号院3号楼2单元401室房屋，建筑面积128.65平方米，总价款人民币12800000元。原告于2023年4月3日通过中国工商银行股份有限公司北京朝阳支行账户6222021123456787向被告支付定金200000元。

另查明，证人周某（系未成年人，2009年5月8日出生，学生，住北京市海淀区中关村南大街5号，公民身份号码110108200905082214，联系电话13711112222）。证人孙丽华，女，1975年2月28日出生，汉族，住广东省广州市天河区体育西路103号，公民身份号码440106197502281234，联系电话13522223333，其名下车辆粤A12345、粤BD12345停放在小区地下车库。证人孙丽华陈述：案发时其登录IP地址192.168.1.100与203.0.113.45，MAC地址00:1A:2B:3C:4D:5E，护照号E12345678，港澳通行证号C87654321。

本案审理过程中，本院依法组成合议庭，由审判长刘振华、审判员杨秀兰、人民陪审员郑国强组成合议庭，书记员方文静担任法庭记录。

依照《中华人民共和国民法典》第五百七十七条、第五百八十五条，《中华人民共和国民事诉讼法》第六十七条之规定，判决如下：

一、被告北京华远置业有限公司于本判决生效之日起十日内返还原告张伟民定金200000元；
二、驳回原告张伟民的其他诉讼请求。

案件受理费4300元，由原告张伟民负担1300元，被告北京华远置业有限公司负担3000元。

如不服本判决，可以在判决书送达之日起十五日内，向本院递交上诉状，并按对方当事人的人数提出副本，上诉于北京市第二中级人民法院。

审 判 长　　刘振华
审 判 员　　杨秀兰
人民陪审员　郑国强

二〇二三年九月二十日

书 记 员　　方文静
"""

# 真值清单（ground truth），验收时按这个核对
GROUND_TRUTH = {
    "PERSON": ["张伟民", "李建国", "王志强", "赵晓东", "陈晓芸", "孙丽华",
               "刘振华", "杨秀兰", "郑国强", "方文静"],
    "ID_CARD": ["11010519870312451X", "310115199211058768",
                "110108200905082214", "440106197502281234"],
    "PHONE": ["13801234567", "13911223344", "13622223333", "13711112222", "13522223333"],
    "TEL": ["010-66554433"],
    "EMAIL": ["zhangwm@example.com.cn"],
    "BANK_CARD": ["6222021123456787"],
    "USCC": ["91110102710931234J"],
    "LICENSE_NO": ["11101201510123456"],
    "PLATE": ["粤A12345", "粤BD12345"],
    "IP_ADDR": ["192.168.1.100", "203.0.113.45"],
    "MAC_ADDR": ["00:1A:2B:3C:4D:5E"],
    "PASSPORT": ["E12345678"],
    "HK_MO_PERMIT": ["C87654321"],
    "IM_ACCOUNT": ["zhangwm1987"],
    "ADDRESS": ["北京市朝阳区建国路88号院3号楼2单元401室",
                "上海市浦东新区世纪大道100号28层",
                "北京市海淀区中关村南大街5号",
                "广东省广州市天河区体育西路103号",
                # 被告住所地：夹在机构名与统一社会信用代码之间，
                # 最容易被 ORG 检测器向前回溯吃掉，必须单独盯着
                "北京市西城区金融大街7号英蓝国际金融中心12层"],
    # 这些是刻意埋进去的"额外泄露点"，正文里没有
    "EXTRA": {
        "header": "（2023）京0102民初18765号　张伟民诉北京华远置业有限公司",
        "footer": "承办人：刘振华　联系电话13801234567　第 1 页",
        "comment_author": "李书记员",
        "comment_text": "已电话核实张伟民身份，号码13801234567无误；陈晓芸系案外人，注意保密。",
        "revision_ins": "住北京市东城区东直门南大街9号",
        "revision_del_phone": "13600001111",
        "doc_author": "王承办法官",
        "doc_last_modified_by": "李书记员",
        "doc_title": "张伟民诉北京华远置业有限公司房屋买卖合同纠纷",
        "doc_keywords": "张伟民;13801234567;内部",
        "seal_text": "北京华远置业有限公司",
    },
}


# --------------------------------------------------------------------------
# 红章图片
# --------------------------------------------------------------------------


def make_seal_image(path: Path, text: str = "北京华远置业有限公司", size: int = 620) -> Path:
    """画一枚红色圆形公章（含五角星与环绕文字），贴在白底上。"""
    from PIL import Image, ImageDraw, ImageFont
    import math

    font_path = "C:/Windows/Fonts/simhei.ttf"
    img = Image.new("RGB", (size, size), "white")
    d = ImageDraw.Draw(img, "RGBA")
    red = (200, 16, 24, 255)
    cx = cy = size / 2
    r_out = size * 0.44

    # 外圈
    d.ellipse([cx - r_out, cy - r_out, cx + r_out, cy + r_out], outline=red, width=10)
    # 五角星
    r_star = size * 0.16
    pts = []
    for i in range(10):
        ang = -math.pi / 2 + i * math.pi / 5
        rr = r_star if i % 2 == 0 else r_star * 0.42
        pts.append((cx + rr * math.cos(ang), cy + rr * math.sin(ang) - size * 0.03))
    d.polygon(pts, fill=red)

    # 环绕文字
    try:
        f_arc = ImageFont.truetype(font_path, int(size * 0.062))
        f_bottom = ImageFont.truetype(font_path, int(size * 0.075))
    except Exception:
        f_arc = f_bottom = ImageFont.load_default()

    chars = list(text)
    arc_r = r_out * 0.80
    total = math.radians(200)
    start = -math.pi / 2 - total / 2
    for i, ch in enumerate(chars):
        ang = start + total * (i + 0.5) / len(chars)
        x = cx + arc_r * math.cos(ang)
        y = cy + arc_r * math.sin(ang)
        tmp = Image.new("RGBA", (int(size * 0.12), int(size * 0.12)), (0, 0, 0, 0))
        td = ImageDraw.Draw(tmp)
        td.text((tmp.width / 2, tmp.height / 2), ch, font=f_arc, fill=red, anchor="mm")
        tmp = tmp.rotate(-math.degrees(ang) - 90, resample=Image.BICUBIC, expand=True)
        img.paste(tmp, (int(x - tmp.width / 2), int(y - tmp.height / 2)), tmp)

    d = ImageDraw.Draw(img, "RGBA")
    d.text((cx, cy + r_out * 0.58), "专用章", font=f_bottom, fill=red, anchor="mm")

    # 贴到白底文档图上，模拟盖章效果
    doc = Image.new("RGB", (1240, 700), "white")
    doc.paste(img, (620, 40))
    dd = ImageDraw.Draw(doc)
    try:
        f_body = ImageFont.truetype(font_path, 22)
    except Exception:
        f_body = ImageFont.load_default()
    dd.text((60, 80), "甲方（盖章）：北京华远置业有限公司", font=f_body, fill="black")
    dd.text((60, 130), "法定代表人：王志强　联系电话：13801234567", font=f_body, fill="black")
    dd.text((60, 180), "住所：北京市西城区金融大街7号英蓝国际金融中心12层", font=f_body, fill="black")
    dd.text((60, 230), "统一社会信用代码：91110102710931234J", font=f_body, fill="black")
    doc.save(path)
    return path


# --------------------------------------------------------------------------
# DOCX：正文 + 页眉页脚 + 批注 + 修订 + 元数据 + 红章图
# --------------------------------------------------------------------------


def make_docx(path: Path) -> Path:
    import docx
    from docx.shared import Pt, Inches

    doc = docx.Document()
    st = doc.styles["Normal"]
    st.font.name = "宋体"
    st.font.size = Pt(12)

    # --- L4 文档属性
    cp = doc.core_properties
    cp.author = GROUND_TRUTH["EXTRA"]["doc_author"]
    cp.last_modified_by = GROUND_TRUTH["EXTRA"]["doc_last_modified_by"]
    cp.title = GROUND_TRUTH["EXTRA"]["doc_title"]
    cp.subject = "内部卷宗"
    cp.keywords = GROUND_TRUTH["EXTRA"]["doc_keywords"]
    cp.comments = "承办人刘振华，联系电话13801234567"
    cp.category = "民事"

    # --- L2 页眉页脚
    sec = doc.sections[0]
    sec.header.paragraphs[0].text = GROUND_TRUTH["EXTRA"]["header"]
    sec.footer.paragraphs[0].text = GROUND_TRUTH["EXTRA"]["footer"]

    # --- L1 正文
    for line in JUDGMENT.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        p = doc.add_paragraph(line)
        p.paragraph_format.first_line_indent = Pt(24)

    # --- 表格（当事人信息汇总，测试表格内 w:p）
    tbl = doc.add_table(rows=4, cols=3)
    tbl.style = "Table Grid"
    rows = [
        ("当事人", "身份号码", "联系电话"),
        ("张伟民", "11010519870312451X", "13801234567"),
        ("陈晓芸", "310115199211058768", "13622223333"),
        ("孙丽华", "440106197502281234", "13522223333"),
    ]
    for i, r in enumerate(rows):
        for j, v in enumerate(r):
            tbl.cell(i, j).text = v

    # --- L9 红章图片
    seal_png = SAMPLES / "_seal.png"
    make_seal_image(seal_png)
    doc.add_paragraph("（以下为签章页）")
    doc.add_picture(str(seal_png), width=Inches(5.5))

    doc.save(str(path))

    # --- L3 修订 + L5 批注：zip 手术注入
    _inject_revisions_and_comments(path)
    return path


def _inject_revisions_and_comments(path: Path) -> None:
    """往 docx 里注入 w:ins / w:del 修订与 comments.xml。"""
    tmp = path.with_suffix(".tmp.docx")
    with zipfile.ZipFile(path, "r") as zin:
        parts = {n: zin.read(n) for n in zin.namelist()}

    # ---- comments.xml
    comments_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:comments xmlns:w="{W}" xmlns:r="{R}">
  <w:comment w:id="1" w:author="{GROUND_TRUTH['EXTRA']['comment_author']}" w:date="2023-09-18T10:22:00Z" w:initials="LS">
    <w:p><w:r><w:t>{GROUND_TRUTH['EXTRA']['comment_text']}</w:t></w:r></w:p>
  </w:comment>
  <w:comment w:id="2" w:author="刘振华" w:date="2023-09-19T09:00:00Z" w:initials="LZH">
    <w:p><w:r><w:t>陈晓芸的港澳通行证号C87654321需核对，另其住址上海市浦东新区世纪大道100号28层已送达。</w:t></w:r></w:p>
  </w:comment>
</w:comments>"""
    parts["word/comments.xml"] = comments_xml.encode("utf-8")

    people_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:people xmlns:w="{W}" xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml">
  <w:person w:author="{GROUND_TRUTH['EXTRA']['comment_author']}"><w15:presenceInfo w15:providerId="None" w15:userId="{GROUND_TRUTH['EXTRA']['comment_author']}"/></w:person>
  <w:person w:author="刘振华"><w15:presenceInfo w15:providerId="None" w15:userId="刘振华"/></w:person>
</w:people>"""
    parts["word/people.xml"] = people_xml.encode("utf-8")

    # ---- [Content_Types].xml 增加 comments / people
    ct = etree.fromstring(parts["[Content_Types].xml"])
    for partname, ctype in (
            ("/word/comments.xml",
             "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"),
            ("/word/people.xml",
             "application/vnd.openxmlformats-officedocument.wordprocessingml.people+xml")):
        if not any(e.get("PartName") == partname for e in ct):
            ov = etree.SubElement(ct, f"{{{CT}}}Override")
            ov.set("PartName", partname)
            ov.set("ContentType", ctype)
    parts["[Content_Types].xml"] = etree.tostring(ct, xml_declaration=True,
                                                  encoding="UTF-8", standalone=True)

    # ---- word/_rels/document.xml.rels 增加关系
    rels = etree.fromstring(parts["word/_rels/document.xml.rels"])
    existing = {r.get("Id") for r in rels}
    rid_c = "rIdCmt100" if "rIdCmt100" not in existing else "rIdCmt101"
    for rid, target, typ in (
            (rid_c, "comments.xml",
             "http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments"),
            ("rIdPpl100", "people.xml",
             "http://schemas.openxmlformats.org/officeDocument/2006/relationships/people")):
        if rid in existing:
            continue
        rel = etree.SubElement(rels, f"{{{REL}}}Relationship")
        rel.set("Id", rid)
        rel.set("Type", typ)
        rel.set("Target", target)
    parts["word/_rels/document.xml.rels"] = etree.tostring(
        rels, xml_declaration=True, encoding="UTF-8", standalone=True)

    # ---- document.xml：注入批注引用 + 修订标记
    doc = etree.fromstring(parts["word/document.xml"])
    body = doc.find(_w("body"))
    paras = [p for p in body.iter(_w("p"))]

    # 批注挂在第 4 段（原告信息段）
    target = None
    for p in paras:
        txt = "".join(t.text or "" for t in p.iter(_w("t")))
        if "张伟民" in txt and "公民身份号码" in txt:
            target = p
            break
    if target is not None and len(target):
        rng_start = etree.Element(_w("commentRangeStart"))
        rng_start.set(_w("id"), "1")
        rng_end = etree.Element(_w("commentRangeEnd"))
        rng_end.set(_w("id"), "1")
        target.insert(0, rng_start)
        ref_run = etree.SubElement(target, _w("r"))
        ref_el = etree.SubElement(ref_run, _w("commentReference"))
        ref_el.set(_w("id"), "1")
        target.append(rng_end)

    # 修订：新增一段，里面同时含 w:ins（新地址）与 w:del（旧电话）
    new_p = etree.SubElement(body, _w("p"))
    r1 = etree.SubElement(new_p, _w("r"))
    t1 = etree.SubElement(r1, _w("t"))
    t1.text = "补充查明：原告原住址"

    ins = etree.SubElement(new_p, _w("ins"))
    ins.set(_w("id"), "9001")
    ins.set(_w("author"), GROUND_TRUTH["EXTRA"]["doc_author"])
    ins.set(_w("date"), "2023-09-15T14:00:00Z")
    ri = etree.SubElement(ins, _w("r"))
    ti = etree.SubElement(ri, _w("t"))
    ti.text = GROUND_TRUTH["EXTRA"]["revision_ins"]

    r2 = etree.SubElement(new_p, _w("r"))
    t2 = etree.SubElement(r2, _w("t"))
    t2.text = "，曾用联系电话"

    dele = etree.SubElement(new_p, _w("del"))
    dele.set(_w("id"), "9002")
    dele.set(_w("author"), GROUND_TRUTH["EXTRA"]["doc_last_modified_by"])
    dele.set(_w("date"), "2023-09-15T14:05:00Z")
    rd = etree.SubElement(dele, _w("r"))
    td = etree.SubElement(rd, _w("delText"))
    td.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    td.text = GROUND_TRUTH["EXTRA"]["revision_del_phone"]

    r3 = etree.SubElement(new_p, _w("r"))
    t3 = etree.SubElement(r3, _w("t"))
    t3.text = "，现已停用。"

    parts["word/document.xml"] = etree.tostring(doc, xml_declaration=True,
                                                encoding="UTF-8", standalone=True)

    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in parts.items():
            z.writestr(n, d)
    shutil.move(str(tmp), str(path))


# --------------------------------------------------------------------------
# PDF：文本版 + 扫描版
# --------------------------------------------------------------------------


def make_text_pdf(path: Path) -> Path:
    """带文本层的 PDF（判决书排版）。"""
    import fitz

    doc = fitz.open()
    doc.set_metadata({
        "author": GROUND_TRUTH["EXTRA"]["doc_author"],
        "title": GROUND_TRUTH["EXTRA"]["doc_title"],
        "subject": "内部卷宗",
        "keywords": GROUND_TRUTH["EXTRA"]["doc_keywords"],
        "creator": "刘振华",
        "producer": "法隐测试样本生成器",
    })
    page = doc.new_page(width=595, height=842)
    y = 60
    for line in JUDGMENT.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        # 手动折行
        while line:
            chunk, line = line[:38], line[38:]
            rc = page.insert_textbox(fitz.Rect(50, y, 545, y + 18), chunk,
                                     fontname="china-s", fontsize=10.5, align=0)
            y += 17
            if y > 790:
                page = doc.new_page(width=595, height=842)
                y = 60
    # 盖章页：贴红章图
    seal = SAMPLES / "_seal.png"
    if not seal.exists():
        make_seal_image(seal)
    page2 = doc.new_page(width=595, height=842)
    page2.insert_image(fitz.Rect(60, 60, 535, 330), filename=str(seal))
    page2.insert_textbox(fitz.Rect(60, 350, 535, 420),
                         "甲方（盖章）：北京华远置业有限公司\n法定代表人：王志强　联系电话：13801234567",
                         fontname="china-s", fontsize=11)
    doc.save(str(path), garbage=3, deflate=True)
    doc.close()
    return path


def make_scanned_pdf(path: Path) -> Path:
    """扫描版 PDF：整页是图片，没有文本层。用来验证视觉+OCR 链路。"""
    import fitz
    from PIL import Image, ImageDraw, ImageFont

    font_path = "C:/Windows/Fonts/simsun.ttc"
    W, H = 1240, 1754
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    try:
        f_title = ImageFont.truetype(font_path, 34)
        f_body = ImageFont.truetype(font_path, 24)
    except Exception:
        f_title = f_body = ImageFont.load_default()

    d.text((W / 2, 70), "北京市西城区人民法院", font=f_title, fill="black", anchor="mm")
    d.text((W / 2, 130), "民 事 判 决 书", font=f_title, fill="black", anchor="mm")
    d.text((W / 2, 190), "（2023）京0102民初18765号", font=f_body, fill="black", anchor="mm")

    y = 250
    for line in JUDGMENT.strip().split("\n")[4:]:
        line = line.strip()
        if not line:
            y += 16
            continue
        while line:
            chunk, line = line[:30], line[30:]
            d.text((90, y), chunk, font=f_body, fill="black")
            y += 38
            if y > H - 160:
                break
        if y > H - 160:
            break

    # 盖一枚红章 + 手写体签名区
    seal = SAMPLES / "_seal.png"
    if not seal.exists():
        make_seal_image(seal)
    simg = Image.open(seal).crop((600, 20, 1240, 660))
    img.paste(simg, (560, H - 620))
    d.text((120, H - 260), "审判长　刘振华", font=f_body, fill="black")
    d.text((120, H - 210), "审判员　杨秀兰", font=f_body, fill="black")
    d.text((120, H - 160), "书记员　方文静", font=f_body, fill="black")

    png = SAMPLES / "_scan_page.png"
    img.save(png)

    doc = fitz.open()
    doc.set_metadata({"author": GROUND_TRUTH["EXTRA"]["doc_author"],
                      "title": "扫描件"})
    page = doc.new_page(width=595, height=842)
    page.insert_image(fitz.Rect(0, 0, 595, 842), filename=str(png))
    doc.save(str(path), garbage=3, deflate=True)
    doc.close()
    return path


# --------------------------------------------------------------------------


def make_txt(path: Path) -> Path:
    txt = JUDGMENT
    txt += "\n\n【附：当事人联系方式清单】\n"
    txt += "张伟民 13801234567 zhangwm@example.com.cn 11010519870312451X\n"
    txt += "陈晓芸 +86 136 2222 3333 310115199211058768\n"
    txt += "孙丽华 13522223333 440106197502281234 粤A12345\n"
    txt += "李建国（律师）13911223344 执业证号11101201510123456 QQ号123456789\n"
    txt += "赵晓东（律师）010-66554433转8021\n"
    path.write_text(txt, encoding="utf-8")
    return path


def make_xlsx(path: Path) -> Path:
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "当事人"
    ws.append(["姓名", "身份号码", "联系电话", "住址", "备注"])
    ws.append(["张伟民", "11010519870312451X", "13801234567",
               "北京市朝阳区建国路88号院3号楼2单元401室", "原告"])
    ws.append(["陈晓芸", "310115199211058768", "13622223333",
               "上海市浦东新区世纪大道100号28层", "第三人"])
    ws.append(["孙丽华", "440106197502281234", "13522223333",
               "广东省广州市天河区体育西路103号", "证人"])
    ws.append(["周某", "110108200905082214", "13711112222",
               "北京市海淀区中关村南大街5号", "证人，系未成年人"])
    ws["F1"] = "合计"
    ws["F2"] = '=CONCATENATE("联系人电话：",C2)'
    ws2 = wb.create_sheet("账户")
    ws2.append(["户名", "开户行", "账号", "金额"])
    ws2.append(["张伟民", "中国工商银行股份有限公司北京朝阳支行", "6222021123456787", 200000])
    ws2.append(["北京华远置业有限公司", "中国建设银行股份有限公司北京西城支行", "1100123456780003", 12800000])
    # 批注
    try:
        from openpyxl.comments import Comment
        ws["A2"].comment = Comment("已核实身份，号码13801234567无误 —— 李书记员", "李书记员")
    except Exception:
        pass
    # 文档属性
    wb.properties.creator = GROUND_TRUTH["EXTRA"]["doc_author"]
    wb.properties.lastModifiedBy = GROUND_TRUTH["EXTRA"]["doc_last_modified_by"]
    wb.properties.title = GROUND_TRUTH["EXTRA"]["doc_title"]
    wb.properties.subject = "内部卷宗"
    wb.properties.keywords = GROUND_TRUTH["EXTRA"]["doc_keywords"]
    wb.save(str(path))
    return path


def make_all() -> dict[str, Path]:
    out = {
        "docx": make_docx(SAMPLES / "民事判决书.docx"),
        "txt": make_txt(SAMPLES / "当事人清单.txt"),
        "pdf_text": make_text_pdf(SAMPLES / "民事判决书_文本版.pdf"),
        "pdf_scan": make_scanned_pdf(SAMPLES / "民事判决书_扫描版.pdf"),
        "xlsx": make_xlsx(SAMPLES / "当事人信息表.xlsx"),
        "image": make_seal_image(SAMPLES / "签章页.png"),
    }
    return out


if __name__ == "__main__":
    for k, v in make_all().items():
        print(f"{k:10} {v}  ({v.stat().st_size} 字节)")
