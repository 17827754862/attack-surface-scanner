from __future__ import annotations

import argparse
import re
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_LINE_SPACING
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Inches, Pt, RGBColor


ROOT = Path(__file__).resolve().parents[1]
MANUAL_MD = ROOT / "docs" / "project-manual" / "ATTACK_SURFACE_SCANNER_MANUAL.md"
OUTPUT = (
    ROOT
    / "docs"
    / "project-manual"
    / "Attack-Surface-Scanner-完整项目说明书-深度设计版.docx"
)
ASSET_ROOT = ROOT / "docs" / "project-manual"

BLACK = "000000"
NAVY = "1F4E78"
LIGHT_BLUE = "D9EAF7"
PALE_BLUE = "F2F6FA"
MID_GRAY = "D9D9D9"
TEXT_GRAY = "444444"
CODE_BG = "F3F5F7"


def set_cell_shading(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def set_cell_margins(cell, top=100, start=120, bottom=100, end=120) -> None:
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    tc_mar = tc_pr.first_child_found_in("w:tcMar")
    if tc_mar is None:
        tc_mar = OxmlElement("w:tcMar")
        tc_pr.append(tc_mar)
    for margin, value in (("top", top), ("start", start), ("bottom", bottom), ("end", end)):
        node = tc_mar.find(qn(f"w:{margin}"))
        if node is None:
            node = OxmlElement(f"w:{margin}")
            tc_mar.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def set_repeat_table_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)


def set_row_cant_split(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    cant_split = OxmlElement("w:cantSplit")
    tr_pr.append(cant_split)


def set_table_borders(table, color=MID_GRAY, size="6") -> None:
    tbl_pr = table._tbl.tblPr
    borders = tbl_pr.first_child_found_in("w:tblBorders")
    if borders is None:
        borders = OxmlElement("w:tblBorders")
        tbl_pr.append(borders)
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        element = borders.find(qn(f"w:{edge}"))
        if element is None:
            element = OxmlElement(f"w:{edge}")
            borders.append(element)
        element.set(qn("w:val"), "single")
        element.set(qn("w:sz"), size)
        element.set(qn("w:space"), "0")
        element.set(qn("w:color"), color)


def set_repeat_header_row(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    element = OxmlElement("w:tblHeader")
    element.set(qn("w:val"), "true")
    tr_pr.append(element)


def set_paragraph_bottom_border(paragraph, color=NAVY, size="8") -> None:
    p_pr = paragraph._p.get_or_add_pPr()
    borders = p_pr.find(qn("w:pBdr"))
    if borders is None:
        borders = OxmlElement("w:pBdr")
        p_pr.append(borders)
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), size)
    bottom.set(qn("w:space"), "5")
    bottom.set(qn("w:color"), color)
    borders.append(bottom)


def add_page_number(paragraph) -> None:
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = paragraph.add_run()
    fld_char_1 = OxmlElement("w:fldChar")
    fld_char_1.set(qn("w:fldCharType"), "begin")
    instr_text = OxmlElement("w:instrText")
    instr_text.set(qn("xml:space"), "preserve")
    instr_text.text = " PAGE "
    fld_char_2 = OxmlElement("w:fldChar")
    fld_char_2.set(qn("w:fldCharType"), "end")
    run._r.append(fld_char_1)
    run._r.append(instr_text)
    run._r.append(fld_char_2)


def configure_document() -> Document:
    doc = Document()
    section = doc.sections[0]
    section.page_width = Cm(21)
    section.page_height = Cm(29.7)
    section.top_margin = Cm(2.0)
    section.bottom_margin = Cm(1.9)
    section.left_margin = Cm(2.2)
    section.right_margin = Cm(2.2)
    section.header_distance = Cm(1.0)
    section.footer_distance = Cm(0.9)

    styles = doc.styles
    normal = styles["Normal"]
    normal.font.name = "Microsoft YaHei"
    normal._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
    normal.font.size = Pt(10.5)
    normal.font.color.rgb = RGBColor.from_string(BLACK)
    normal.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
    normal.paragraph_format.space_after = Pt(6)

    title = styles["Title"]
    title.font.name = "Microsoft YaHei"
    title._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
    title.font.size = Pt(28)
    title.font.bold = True
    title.font.color.rgb = RGBColor.from_string(BLACK)

    for name, size, before, after in (
        ("Heading 1", 18, 18, 10),
        ("Heading 2", 14, 14, 7),
        ("Heading 3", 12, 10, 5),
    ):
        style = styles[name]
        style.font.name = "Microsoft YaHei"
        style._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = RGBColor.from_string(BLACK)
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)
        style.paragraph_format.keep_with_next = True
        style.paragraph_format.page_break_before = name == "Heading 1"

    for name in ("List Bullet", "List Number"):
        style = styles[name]
        style.font.name = "Microsoft YaHei"
        style._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
        style.font.size = Pt(10.5)
        style.paragraph_format.line_spacing = 1.45
        style.paragraph_format.space_after = Pt(3)

    header = section.header
    hp = header.paragraphs[0]
    hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    hr = hp.add_run("Attack Surface Scanner 完整项目说明书 · 深度设计版")
    hr.font.name = "Microsoft YaHei"
    hr._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
    hr.font.size = Pt(8)
    hr.font.color.rgb = RGBColor(98, 98, 98)

    footer = section.footer
    fp = footer.paragraphs[0]
    footer_text = fp.add_run("版本 2.0 深度设计版  |  ")
    footer_text.font.name = "Microsoft YaHei"
    footer_text._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
    footer_text.font.size = Pt(8)
    footer_text.font.color.rgb = RGBColor(98, 98, 98)
    add_page_number(fp)

    props = doc.core_properties
    props.title = "Attack Surface Scanner 完整项目说明书（深度设计版）"
    props.subject = "授权资产攻击面侦察与漏洞定位系统的架构、源码、验证与实验设计"
    props.author = "Codex"
    props.keywords = "攻击面扫描, LangGraph, 漏洞评估, 多引擎, Docker"
    return doc


def parse_inline(paragraph, text: str, *, bold: bool = False, color: str | None = None) -> None:
    token_re = re.compile(r"(\*\*.+?\*\*|`[^`]+`)")
    cursor = 0
    for match in token_re.finditer(text):
        if match.start() > cursor:
            run = paragraph.add_run(text[cursor : match.start()])
            run.bold = bold
            if color:
                run.font.color.rgb = RGBColor.from_string(color)
        token = match.group(0)
        if token.startswith("**"):
            run = paragraph.add_run(token[2:-2])
            run.bold = True
        else:
            run = paragraph.add_run(token[1:-1])
            run.font.name = "Consolas"
            run._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
            run.font.size = Pt(9)
            run.font.color.rgb = RGBColor.from_string("1F4E78")
        cursor = match.end()
    if cursor < len(text):
        run = paragraph.add_run(text[cursor:])
        run.bold = bold
        if color:
            run.font.color.rgb = RGBColor.from_string(color)


def add_body_paragraph(doc: Document, text: str) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.first_line_indent = Cm(0.74)
    p.paragraph_format.space_after = Pt(6)
    parse_inline(p, text)


def create_decimal_numbering(doc: Document) -> str:
    numbering = doc.part.numbering_part.element
    abstract_ids = [
        int(item.get(qn("w:abstractNumId")))
        for item in numbering.findall(qn("w:abstractNum"))
    ]
    number_ids = [
        int(item.get(qn("w:numId")))
        for item in numbering.findall(qn("w:num"))
    ]
    abstract_id = max(abstract_ids, default=0) + 1
    number_id = max(number_ids, default=0) + 1

    abstract_num = OxmlElement("w:abstractNum")
    abstract_num.set(qn("w:abstractNumId"), str(abstract_id))
    multi_level = OxmlElement("w:multiLevelType")
    multi_level.set(qn("w:val"), "singleLevel")
    abstract_num.append(multi_level)
    level = OxmlElement("w:lvl")
    level.set(qn("w:ilvl"), "0")
    for tag, value in (
        ("w:start", "1"),
        ("w:numFmt", "decimal"),
        ("w:lvlText", "%1."),
        ("w:lvlJc", "left"),
    ):
        item = OxmlElement(tag)
        item.set(qn("w:val"), value)
        level.append(item)
    p_pr = OxmlElement("w:pPr")
    indentation = OxmlElement("w:ind")
    indentation.set(qn("w:left"), "720")
    indentation.set(qn("w:hanging"), "360")
    p_pr.append(indentation)
    level.append(p_pr)
    abstract_num.append(level)

    first_num = numbering.find(qn("w:num"))
    if first_num is None:
        numbering.append(abstract_num)
    else:
        first_num.addprevious(abstract_num)

    num = OxmlElement("w:num")
    num.set(qn("w:numId"), str(number_id))
    abstract_ref = OxmlElement("w:abstractNumId")
    abstract_ref.set(qn("w:val"), str(abstract_id))
    num.append(abstract_ref)
    numbering.append(num)
    return str(number_id)


def add_list_item(
    doc: Document,
    text: str,
    ordered: bool,
    ordered_num_id: str | None = None,
) -> None:
    style = "List Bullet"
    p = doc.add_paragraph(style=style)
    if ordered:
        p.style = doc.styles["Normal"]
        p.paragraph_format.left_indent = Cm(1.0)
        p.paragraph_format.first_line_indent = Cm(-0.6)
        p_pr = p._p.get_or_add_pPr()
        num_pr = OxmlElement("w:numPr")
        ilvl = OxmlElement("w:ilvl")
        ilvl.set(qn("w:val"), "0")
        num_id = OxmlElement("w:numId")
        num_id.set(qn("w:val"), str(ordered_num_id or 1))
        num_pr.append(ilvl)
        num_pr.append(num_id)
        p_pr.append(num_pr)
    parse_inline(p, text)


def add_code_block(doc: Document, text: str) -> None:
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    set_row_cant_split(table.rows[0])
    table.columns[0].width = Cm(16.4)
    cell = table.cell(0, 0)
    cell.width = Cm(16.4)
    set_cell_shading(cell, CODE_BG)
    set_cell_margins(cell, top=120, start=160, bottom=120, end=160)
    paragraph = cell.paragraphs[0]
    paragraph.paragraph_format.space_after = Pt(0)
    paragraph.paragraph_format.line_spacing = 1.1
    run = paragraph.add_run(text.rstrip())
    run.font.name = "Consolas"
    run._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
    run.font.size = Pt(8.5)
    run.font.color.rgb = RGBColor.from_string("222222")
    spacer = doc.add_paragraph()
    spacer.paragraph_format.space_after = Pt(2)


def add_markdown_table(doc: Document, rows: list[list[str]]) -> None:
    if not rows:
        return
    column_count = max(len(row) for row in rows)
    normalized = [row + [""] * (column_count - len(row)) for row in rows]
    content_width = 16.4
    max_lengths = []
    for column in range(column_count):
        max_lengths.append(max(len(normalized[row][column]) for row in range(len(normalized))))
    weights = [min(4.5, max(1.0, length / 14)) for length in max_lengths]
    total_weight = sum(weights)
    widths = [content_width * weight / total_weight for weight in weights]

    table = doc.add_table(rows=len(normalized), cols=column_count)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    set_table_borders(table)
    for index, width in enumerate(widths):
        table.columns[index].width = Cm(width)

    for row_index, row in enumerate(normalized):
        table_row = table.rows[row_index]
        set_row_cant_split(table_row)
        if row_index == 0:
            set_repeat_header_row(table_row)
        for column_index, value in enumerate(row):
            cell = table_row.cells[column_index]
            cell.width = Cm(widths[column_index])
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            set_cell_margins(cell)
            if row_index == 0:
                set_cell_shading(cell, NAVY)
            elif row_index % 2 == 0:
                set_cell_shading(cell, PALE_BLUE)
            paragraph = cell.paragraphs[0]
            paragraph.paragraph_format.space_after = Pt(0)
            paragraph.paragraph_format.line_spacing = 1.15
            if row_index == 0:
                run = paragraph.add_run(value)
                run.bold = True
                run.font.size = Pt(8.5)
                run.font.color.rgb = RGBColor(255, 255, 255)
            else:
                parse_inline(paragraph, value)
                for run in paragraph.runs:
                    run.font.size = Pt(8.5)

    spacer = doc.add_paragraph()
    spacer.paragraph_format.space_after = Pt(2)


def add_image(doc: Document, path: Path, alt_text: str) -> None:
    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.space_before = Pt(6)
    paragraph.paragraph_format.space_after = Pt(4)
    run = paragraph.add_run()
    run.add_picture(str(path), width=Cm(16.2))
    caption = doc.add_paragraph()
    caption.alignment = WD_ALIGN_PARAGRAPH.CENTER
    caption.paragraph_format.space_after = Pt(8)
    run = caption.add_run(alt_text)
    run.font.size = Pt(8.5)
    run.font.color.rgb = RGBColor(90, 90, 90)


def add_cover(doc: Document, headings: list[str]) -> None:
    top = doc.add_paragraph()
    top.paragraph_format.space_before = Pt(48)
    top.paragraph_format.space_after = Pt(28)
    run = top.add_run("技术说明书  /  PROJECT MANUAL")
    run.bold = True
    run.font.size = Pt(10)
    run.font.color.rgb = RGBColor.from_string(NAVY)

    title = doc.add_paragraph(style="Title")
    title.paragraph_format.space_after = Pt(14)
    title.add_run("Attack Surface Scanner\n完整项目说明书")

    subtitle = doc.add_paragraph()
    subtitle.paragraph_format.space_after = Pt(18)
    run = subtitle.add_run("深度设计版 · 架构、源码、工具调用与有效性验证")
    run.font.size = Pt(15)
    run.font.color.rgb = RGBColor.from_string(TEXT_GRAY)

    intro = doc.add_paragraph()
    intro.paragraph_format.space_after = Pt(40)
    run = intro.add_run(
        "从容器运行时、API 与数据模型，到 LangGraph 全节点、14 类扫描引擎、"
        "前端实现、安全边界、融合实验、替代人工验证与二次开发。"
    )
    run.font.size = Pt(11)
    run.font.color.rgb = RGBColor.from_string(TEXT_GRAY)

    meta = doc.add_table(rows=5, cols=2)
    meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta.autofit = False
    set_table_borders(meta)
    rows = [
        ("文档版本", "2.0 深度设计版"),
        ("编制日期", "2026-11-05"),
        ("项目版本", "0.1.0"),
        ("适用对象", "使用者、运维、开发、答辩与评审"),
        ("覆盖范围", "设计取舍、源码调用链、工具执行、融合实验与验证"),
    ]
    for index, (label, value) in enumerate(rows):
        left, right = meta.rows[index].cells
        left.width = Cm(4.0)
        right.width = Cm(10.0)
        set_cell_shading(left, LIGHT_BLUE)
        set_cell_margins(left)
        set_cell_margins(right)
        left.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        right.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p_left = left.paragraphs[0]
        p_left.paragraph_format.space_after = Pt(0)
        r_left = p_left.add_run(label)
        r_left.bold = True
        r_left.font.size = Pt(10)
        p_right = right.paragraphs[0]
        p_right.paragraph_format.space_after = Pt(0)
        r_right = p_right.add_run(value)
        r_right.font.size = Pt(10)

    doc.add_page_break()
    heading = doc.add_paragraph()
    heading.paragraph_format.space_after = Pt(12)
    run = heading.add_run("内容导航")
    run.bold = True
    run.font.size = Pt(20)

    for index, text in enumerate(headings, start=1):
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Cm(0.6)
        p.paragraph_format.space_after = Pt(3)
        run = p.add_run(f"{index:02d}  {text}")
        run.font.size = Pt(10.5)
    doc.add_page_break()


def build_docx(source: Path, output: Path) -> None:
    lines = source.read_text(encoding="utf-8").splitlines()
    headings = [line[3:].strip() for line in lines if line.startswith("## ")]
    doc = configure_document()
    add_cover(doc, headings)

    paragraph_buffer: list[str] = []
    table_buffer: list[list[str]] = []
    in_code = False
    code_buffer: list[str] = []
    started = False
    ordered_num_id: str | None = None

    def flush_paragraph() -> None:
        nonlocal paragraph_buffer
        if paragraph_buffer:
            add_body_paragraph(doc, " ".join(item.strip() for item in paragraph_buffer))
            paragraph_buffer = []

    def flush_table() -> None:
        nonlocal table_buffer
        if table_buffer:
            add_markdown_table(doc, table_buffer)
            table_buffer = []

    def flush_code() -> None:
        nonlocal code_buffer
        if code_buffer:
            add_code_block(doc, "\n".join(code_buffer))
            code_buffer = []

    for line in lines:
        if not started:
            if line.startswith("## "):
                started = True
            else:
                continue
        if line.startswith("```"):
            if in_code:
                flush_code()
                in_code = False
            else:
                flush_paragraph()
                flush_table()
                in_code = True
            continue
        if in_code:
            code_buffer.append(line)
            continue
        if line.startswith("# "):
            flush_paragraph()
            flush_table()
            continue
        if line.startswith("## "):
            flush_paragraph()
            flush_table()
            doc.add_heading(line[3:].strip(), level=1)
            continue
        if line.startswith("### "):
            flush_paragraph()
            flush_table()
            doc.add_heading(line[4:].strip(), level=2)
            continue
        if line.startswith("#### "):
            flush_paragraph()
            flush_table()
            doc.add_heading(line[5:].strip(), level=3)
            continue
        if line.startswith("|"):
            flush_paragraph()
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                continue
            table_buffer.append(cells)
            continue
        flush_table()
        if line.startswith("- "):
            flush_paragraph()
            ordered_num_id = None
            add_list_item(doc, line[2:].strip(), ordered=False)
            continue
        if re.match(r"^\d+\.\s+", line):
            flush_paragraph()
            text = re.sub(r"^\d+\.\s+", "", line)
            if ordered_num_id is None:
                ordered_num_id = create_decimal_numbering(doc)
            add_list_item(
                doc,
                text,
                ordered=True,
                ordered_num_id=ordered_num_id,
            )
            continue
        if line.startswith("!["):
            flush_paragraph()
            match = re.match(r"!\[(.*?)\]\((.*?)\)", line)
            if match:
                alt_text, path = match.groups()
                image_path = (source.parent / path).resolve()
                if image_path.exists():
                    add_image(doc, image_path, alt_text)
            continue
        if line.strip() == "<!-- pagebreak -->":
            flush_paragraph()
            doc.add_page_break()
            continue
        if not line.strip():
            flush_paragraph()
            table_buffer and flush_table()
            ordered_num_id = None
            continue
        ordered_num_id = None
        paragraph_buffer.append(line)

    flush_paragraph()
    flush_table()
    flush_code()
    output.parent.mkdir(parents=True, exist_ok=True)
    doc.save(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=str(MANUAL_MD))
    parser.add_argument("--output", default=str(OUTPUT))
    args = parser.parse_args()
    build_docx(Path(args.source), Path(args.output))
    print(Path(args.output))


if __name__ == "__main__":
    main()
