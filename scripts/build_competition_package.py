from __future__ import annotations

from pathlib import Path
from textwrap import wrap

from PIL import Image, ImageDraw, ImageFont
from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs" / "competition"
ASSET_DIR = OUT_DIR / "assets"
DOCX_PATH = OUT_DIR / "传智杯-攻击面扫描系统-技术文档.docx"

NAVY = "0F2742"
BLUE = "1F5F99"
BLUE_LIGHT = "DCEAF6"
TEAL = "1A7F75"
GREEN_LIGHT = "DDF2E9"
AMBER = "A56514"
AMBER_LIGHT = "FFF1D6"
RED = "B42318"
RED_LIGHT = "FCE7E5"
INK = "172033"
MUTED = "586474"
LINE = "CBD5E1"
CANVAS = "F7F9FC"
WHITE = "FFFFFF"

FONT_PATH = Path(r"C:\Windows\Fonts\msyh.ttc")
BOLD_FONT_PATH = Path(r"C:\Windows\Fonts\msyhbd.ttc")
if not BOLD_FONT_PATH.exists():
    BOLD_FONT_PATH = FONT_PATH


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    path = BOLD_FONT_PATH if bold else FONT_PATH
    return ImageFont.truetype(str(path), size=size)


def text_width(draw: ImageDraw.ImageDraw, value: str, selected_font) -> int:
    return int(draw.textbbox((0, 0), value, font=selected_font)[2])


def wrap_lines(draw: ImageDraw.ImageDraw, value: str, selected_font, max_width: int) -> list[str]:
    lines: list[str] = []
    for raw in value.split("\n"):
        current = ""
        for char in raw:
            candidate = current + char
            if current and text_width(draw, candidate, selected_font) > max_width:
                lines.append(current)
                current = char
            else:
                current = candidate
        lines.append(current)
    return lines


def draw_text(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    value: str,
    selected_font,
    fill: str = INK,
    max_width: int | None = None,
    align: str = "center",
    spacing: int = 8,
) -> None:
    lines = wrap_lines(draw, value, selected_font, max_width) if max_width else value.split("\n")
    line_height = selected_font.size + spacing
    total_height = line_height * len(lines)
    x, y = xy
    if align == "center":
        y -= total_height // 2
    elif align == "bottom":
        y -= total_height
    for line in lines:
        width = text_width(draw, line, selected_font)
        draw_x = x - width // 2 if align == "center" else x
        draw.text((draw_x, y), line, font=selected_font, fill=f"#{fill}")
        y += line_height


def box(
    draw: ImageDraw.ImageDraw,
    bounds: tuple[int, int, int, int],
    title: str,
    body: str = "",
    fill: str = WHITE,
    border: str = LINE,
    title_color: str = INK,
    body_color: str = MUTED,
    title_size: int = 30,
    body_size: int = 23,
    index: str = "",
) -> None:
    left, top, right, bottom = bounds
    draw.rounded_rectangle(bounds, radius=20, fill=f"#{fill}", outline=f"#{border}", width=3)
    center_x = (left + right) // 2
    if index:
        draw.ellipse((left + 18, top + 18, left + 58, top + 58), fill=f"#{BLUE}")
        draw_text(
            draw,
            (left + 38, top + 38),
            index,
            font(20, True),
            WHITE,
            align="center",
        )
    draw_text(
        draw,
        (center_x, top + (58 if index else 48)),
        title,
        font(title_size, True),
        title_color,
        max_width=right - left - 42,
        align="center",
    )
    if body:
        height = bottom - top
        draw_text(
            draw,
            (center_x, top + 108 if height < 190 else top + int(height * 0.66)),
            body,
            font(body_size),
            body_color,
            max_width=right - left - 42,
            align="center",
        )


def arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    color: str = "486581",
    width: int = 5,
    label: str = "",
) -> None:
    draw.line([start, end], fill=f"#{color}", width=width)
    dx = end[0] - start[0]
    dy = end[1] - start[1]
    length = max(1, (dx * dx + dy * dy) ** 0.5)
    ux, uy = dx / length, dy / length
    px, py = -uy, ux
    tip = end
    base_x = end[0] - ux * 26
    base_y = end[1] - uy * 26
    points = [
        tip,
        (int(base_x + px * 12), int(base_y + py * 12)),
        (int(base_x - px * 12), int(base_y - py * 12)),
    ]
    draw.polygon(points, fill=f"#{color}")
    if label:
        mid = ((start[0] + end[0]) // 2, (start[1] + end[1]) // 2 - 28)
        draw_text(draw, mid, label, font(18, True), BLUE)


def base_canvas(title: str, subtitle: str = "") -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (1800, 1050), f"#{CANVAS}")
    draw = ImageDraw.Draw(image)
    draw_text(draw, (90, 78), title, font(42, True), NAVY, align="left")
    if subtitle:
        draw_text(draw, (90, 132), subtitle, font(23), MUTED, align="left")
    return image, draw


def save(image: Image.Image, name: str) -> Path:
    path = ASSET_DIR / name
    image.save(path, quality=95)
    return path


def diagram_overview() -> Path:
    image, draw = base_canvas("项目定位：从多工具碎片到可复核的攻击面评估闭环")
    problems = [
        ("工具结果割裂", "格式、严重度、证据不统一"),
        ("流程不可见", "不知道执行了哪些扫描器"),
        ("结果不可复核", "缺少证据链与可重复记录"),
    ]
    outputs = [
        ("统一 Finding", "标准化漏洞实例"),
        ("风险组与评分", "多来源印证与优先级"),
        ("报告与证据", "HTML / JSON / 工作流图"),
    ]
    for i, (title, body) in enumerate(problems):
        top = 240 + i * 210
        box(draw, (90, top, 500, top + 150), title, body, WHITE, LINE, RED, MUTED, 28, 20)
    for i, (title, body) in enumerate(outputs):
        top = 240 + i * 210
        box(draw, (1300, top, 1710, top + 150), title, body, GREEN_LIGHT, "9BCBBE", TEAL, MUTED, 28, 20)

    box(
        draw,
        (620, 260, 1180, 760),
        "Attack Surface Scanner",
        "授权门禁\n动态 AI 编排\n多引擎扫描\n统一融合\n证据与报告",
        BLUE_LIGHT,
        "8CB6D8",
        NAVY,
        BLUE,
        36,
        24,
    )
    for i in range(3):
        top = 315 + i * 210
        arrow(draw, (505, top), (610, top), label="统一" if i == 0 else "")
        arrow(draw, (1185, top), (1290, top), label="输出" if i == 0 else "")
    return save(image, "01-overview.png")


def diagram_architecture() -> Path:
    image, draw = base_canvas("系统架构：控制面、执行面与外部工具隔离")
    bands = [
        ("交互层", 210, 390, [("React + Vite 控制台", "登录 / 配置 / 数据流 / 报告")]),
        ("控制面", 420, 600, [("FastAPI", "JWT / 任务 API / SSE"), ("PostgreSQL", "任务 / 审计 / 快照"), ("Redis", "队列 / 事件")]),
        ("编排面", 630, 810, [("Celery Worker", "LangGraph 状态机"), ("AI Router", "候选工具动态选择"), ("Fallback", "固定安全顺序")]),
        ("执行面", 840, 1020, [("本地 CLI", "Subfinder / dnsx / httpx / Nmap"), ("Nuclei / Wapiti", "模板与参数扫描"), ("外部服务", "ZAP / OpenVAS / OAST")]),
    ]
    for label, top, bottom, items in bands:
        draw_text(draw, (105, (top + bottom) // 2), label, font(26, True), NAVY, align="left")
        width = 1380 // len(items)
        for index, (title, body) in enumerate(items):
            left = 235 + index * width
            box(draw, (left, top, left + width - 22, bottom), title, body, WHITE, LINE, NAVY, MUTED, 26, 20)
        if top != 840:
            arrow(draw, (900, bottom + 8), (900, bottom + 32))
    return save(image, "02-architecture.png")


def diagram_requirements() -> Path:
    image, draw = base_canvas("需求映射：从约束到确定性的设计响应")
    items = [
        ("合法扫描", "授权确认\nScope Guard\nCIDR 校验", BLUE_LIGHT, "8CB6D8"),
        ("长任务控制", "Celery 异步\n阶段预算\n取消与恢复", GREEN_LIGHT, "9BCBBE"),
        ("异构工具", "BaseAdapter\n统一 Finding\n超时与解析", WHITE, LINE),
        ("可复核结果", "证据文件\nSHA-256\n风险组来源", BLUE_LIGHT, "8CB6D8"),
        ("AI 不确定性", "候选白名单\nJSON 校验\n固定回退", AMBER_LIGHT, "E2BE78"),
        ("可恢复执行", "LangGraph\ncheckpoint\nresume_state", GREEN_LIGHT, "9BCBBE"),
    ]
    for index, (title, body, fill, border) in enumerate(items):
        top = 190 + index * 130
        draw.rounded_rectangle((100, top, 610, top + 108), radius=18, fill=f"#{fill}", outline=f"#{border}", width=3)
        draw.rounded_rectangle((780, top, 1700, top + 108), radius=18, fill=f"#{WHITE}", outline=f"#{LINE}", width=3)
        draw_text(draw, (355, top + 32), title, font(23, True), NAVY)
        draw_text(draw, (355, top + 76), body.replace("\n", " · "), font(17), MUTED, max_width=470)
        draw_text(draw, (1240, top + 32), "设计响应", font(23, True), NAVY)
        draw_text(draw, (1240, top + 76), body.replace("\n", "  /  "), font(17), MUTED, max_width=850)
        arrow(draw, (620, top + 54), (760, top + 54))
    draw_text(draw, (900, 985), "确定性边界优先，AI 只优化候选空间内的下一步", font(25, True), BLUE)
    return save(image, "10-requirements.png")


def diagram_dataflow() -> Path:
    image, draw = base_canvas("真实数据流：工具按执行结果逐步出现")
    row1 = [
        ("01", "授权与目标", "scope / CIDR"),
        ("02", "资产发现", "Subfinder / dnsx"),
        ("03", "HTTP / 端口", "httpx / Nmap"),
        ("04", "认证分析", "Cookie / 会话"),
        ("05", "AI Router", "选择下一工具"),
    ]
    row2 = [
        ("06", "动态扫描", "ZAP / Nuclei / API"),
        ("07", "主动验证", "safe / OAST"),
        ("08", "归一化", "别名 / 去重"),
        ("09", "证据链", "SHA-256"),
        ("10", "报告", "HTML / JSON / PNG"),
    ]
    for row_index, items in enumerate((row1, row2)):
        top = 250 + row_index * 340
        for index, item in enumerate(items):
            left = 80 + index * 340
            box(
                draw,
                (left, top, left + 290, top + 220),
                item[1],
                item[2],
                WHITE if row_index == 0 else GREEN_LIGHT,
                LINE if row_index == 0 else "9BCBBE",
                NAVY,
                MUTED,
                27,
                21,
                item[0],
            )
            if index < 4:
                if row_index == 0:
                    arrow(draw, (left + 295, top + 110), (left + 330, top + 110))
                else:
                    arrow(draw, (left + 295, top + 110), (left + 330, top + 110))
    draw.line([(1620, 475), (1620, 550), (215, 550), (215, 585)], fill="#486581", width=5)
    arrow(draw, (215, 555), (215, 585))
    return save(image, "03-dataflow.png")


def diagram_ai_router() -> Path:
    image, draw = base_canvas("AI 动态编排：模型只能选择候选工具")
    nodes = [
        ("确定性候选生成", "scope / mode / profile", BLUE_LIGHT, "8CB6D8"),
        ("读取前序结果", "Finding / 错误 / 端点", WHITE, LINE),
        ("模型选择", "下一工具或 finish", AMBER_LIGHT, "E2BE78"),
        ("合法性校验", "候选白名单 / JSON", GREEN_LIGHT, "9BCBBE"),
        ("执行选定工具", "扫描结果回填 State", WHITE, LINE),
    ]
    for index, (title, body, fill, border) in enumerate(nodes):
        left = 55 + index * 345
        box(draw, (left, 260, left + 290, 510), title, body, fill, border, NAVY, MUTED, 23, 18, f"{index + 1:02d}")
        if index < len(nodes) - 1:
            arrow(draw, (left + 295, 385), (left + 330, 385))
    box(draw, (390, 700, 820, 890), "模型不可用或输出非法", "超时 · 未配置 · 非候选节点\n自动回退固定安全顺序", RED_LIGHT, "E7ABA5", RED, MUTED, 23, 18)
    box(draw, (960, 700, 1410, 890), "下一次判断", "结果写回 State\n重新生成剩余候选", GREEN_LIGHT, "9BCBBE", TEAL, MUTED, 23, 18)
    arrow(draw, (890, 795), (950, 795), color="B42318")
    draw.line([(1410, 795), (1620, 795), (1620, 610)], fill=f"#{BLUE}", width=5)
    arrow(draw, (1620, 650), (1620, 520), color=BLUE, label="loop")
    return save(image, "04-ai-router.png")


def diagram_security() -> Path:
    image, draw = base_canvas("安全门禁：每一步都在确定性边界内")
    gates = [
        ("授权确认", "后端强制 403"),
        ("Scope Guard", "目标 / 重定向 / OpenAPI"),
        ("CIDR 校验", "阻止 DNS 重绑定"),
        ("速率与预算", "max_rps ≤ 5"),
        ("执行隔离", "只读 / drop caps"),
        ("证据与脱敏", "SHA-256 / 递归脱敏"),
    ]
    for index, (title, body) in enumerate(gates):
        row, column = divmod(index, 3)
        left = 100 + column * 560
        top = 290 + row * 300
        box(draw, (left, top, left + 500, top + 210), title, body, BLUE_LIGHT if row == 0 else GREEN_LIGHT, "8CB6D8" if row == 0 else "9BCBBE", NAVY, MUTED, 30, 22)
        if column < 2:
            arrow(draw, (left + 505, top + 105), (left + 545, top + 105))
    draw_text(draw, (900, 900), "AI 不生成命令、不增加目标、不绕过门禁", font(28, True), RED)
    return save(image, "05-security.png")


def diagram_fusion() -> Path:
    image, draw = base_canvas("多引擎融合：从原始输出到可阅读风险组")
    stages = [
        ("原始工具输出", "ZAP · Wapiti · Nuclei\nNmap · OpenVAS · OAST", WHITE, LINE),
        ("统一 Finding", "source / host / url\nseverity / evidence", BLUE_LIGHT, "8CB6D8"),
        ("确定性融合", "别名归一 · 指纹去重\n交叉来源 · 置信度", GREEN_LIGHT, "9BCBBE"),
        ("风险组", "host + port + type\nURL 数与来源", AMBER_LIGHT, "E2BE78"),
    ]
    for index, (title, body, fill, border) in enumerate(stages):
        left = 80 + index * 430
        box(draw, (left, 280, left + 350, 560), title, body, fill, border, NAVY, MUTED, 27, 21)
        if index < 3:
            arrow(draw, (left + 355, 420), (left + 405, 420))
    box(draw, (320, 720, 780, 930), "证据文件", "evidence/*.json\nSHA-256 校验", WHITE, LINE, NAVY, MUTED, 27, 21)
    box(draw, (850, 720, 1310, 930), "风险组详情", "解读 / 修复 / 复测\n误报检查", WHITE, LINE, NAVY, MUTED, 27, 21)
    arrow(draw, (1110, 565), (1110, 710))
    arrow(draw, (770, 825), (840, 825))
    return save(image, "06-fusion.png")


def diagram_deployment() -> Path:
    image, draw = base_canvas("部署拓扑：本地优先的 Docker Compose 架构")
    row = [
        ("浏览器", "React / Vite", WHITE, LINE),
        ("前端", "Nginx / 静态资源", BLUE_LIGHT, "8CB6D8"),
        ("FastAPI", "JWT / REST / SSE", GREEN_LIGHT, "9BCBBE"),
        ("Worker", "LangGraph + 扫描 CLI", AMBER_LIGHT, "E2BE78"),
        ("外部工具", "ZAP / OpenVAS / OAST", BLUE_LIGHT, "8CB6D8"),
    ]
    for index, (title, body, fill, border) in enumerate(row):
        left = 55 + index * 345
        box(draw, (left, 310, left + 285, 570), title, body, fill, border, NAVY, MUTED, 24, 18)
        if index < len(row) - 1:
            arrow(draw, (left + 290, 440), (left + 330, 440))
    box(draw, (727, 710, 1047, 900), "PostgreSQL", "任务 / 快照 / checkpoint", WHITE, LINE, NAVY, MUTED, 25, 18)
    box(draw, (1072, 710, 1392, 900), "Redis", "Celery / SSE PubSub", WHITE, LINE, NAVY, MUTED, 25, 18)
    arrow(draw, (887, 705), (887, 580))
    arrow(draw, (1232, 705), (1232, 580))
    return save(image, "07-deployment.png")


def diagram_core_pipeline() -> Path:
    image, draw = base_canvas("核心调用链：API、Worker 与扫描适配器")
    stages = [
        ("提交任务", "Pydantic + Guard", "202 queued"),
        ("Celery", "Redis broker", "异步执行"),
        ("LangGraph", "状态机 checkpoint", "节点调度"),
        ("BaseAdapter", "CLI / REST / GMP", "工具调用"),
        ("Finding", "归一化 + 指纹", "证据写入"),
        ("Report", "Jinja2 + Mermaid", "HTML / JSON"),
    ]
    for index, (title, body, output) in enumerate(stages):
        left = 50 + index * 292
        fill = GREEN_LIGHT if index >= 4 else WHITE
        border = "9BCBBE" if index >= 4 else LINE
        box(draw, (left, 310, left + 245, 610), title, body, fill, border, NAVY, MUTED, 24, 18, f"{index + 1:02d}")
        draw_text(draw, (left + 122, 690), output, font(20, True), BLUE)
        if index < len(stages) - 1:
            arrow(draw, (left + 250, 460), (left + 282, 460))
    return save(image, "11-core-pipeline.png")


def diagram_experiment() -> Path:
    image, draw = base_canvas("验证路线：从单引擎对照到人机协同")
    groups = [
        ("人工基线", "时间动作研究"),
        ("单引擎", "Nuclei 对照"),
        ("三引擎", "ZAP + Wapiti + Nuclei"),
        ("完整 Agent", "确定性融合"),
        ("未来融合算法", "加权 / 证据一致性"),
        ("人工复核", "人机协同上限"),
    ]
    for index, (title, body) in enumerate(groups):
        left = 60 + index * 290
        fill = GREEN_LIGHT if index >= 4 else WHITE
        border = "9BCBBE" if index >= 4 else LINE
        box(draw, (left, 250, left + 250, 470), title, body, fill, border, NAVY, MUTED, 23, 18)
        if index < len(groups) - 1:
            arrow(draw, (left + 255, 360), (left + 282, 360))
    metrics = [
        ("Recall", "覆盖多少真风险"),
        ("Precision", "减少误报"),
        ("人工时间", "复核与报告"),
        ("稳定性", "Jaccard / 方差"),
    ]
    for index, (title, body) in enumerate(metrics):
        left = 100 + index * 420
        box(draw, (left, 720, left + 360, 900), title, body, BLUE_LIGHT, "8CB6D8", NAVY, MUTED, 27, 20)
    return save(image, "08-experiment.png")


def diagram_test_pipeline() -> Path:
    image, draw = base_canvas("质量门禁：从静态检查到靶场验收")
    layers = [
        ("Python 编译", "语法与模块入口"),
        ("单元测试", "Schema / Guard / 预算"),
        ("适配器测试", "命令参数与解析器"),
        ("API 与图测试", "JWT / 路由 / 恢复"),
        ("前端构建", "Vite 生产构建"),
        ("Compose 验收", "base / full profile"),
        ("靶场验收", "DVWA / Mock\nOpenVAS"),
    ]
    for index, (title, body) in enumerate(layers):
        left = 80 + index * 245
        top = 340
        fill = GREEN_LIGHT if index >= 5 else WHITE
        border = "9BCBBE" if index >= 5 else LINE
        box(draw, (left, top, left + 205, top + 230), title, body, fill, border, NAVY, MUTED, 21, 17)
        if index < len(layers) - 1:
            arrow(draw, (left + 210, top + 115), (left + 235, top + 115))
    draw_text(draw, (900, 815), "当前结果：66 passed · 前端构建通过 · Compose 配置通过", font(28, True), TEAL)
    return save(image, "12-test-pipeline.png")


def diagram_innovation() -> Path:
    image, draw = base_canvas("创新点：技术创新与应用创新")
    tech = [
        ("01", "AI 只在候选工具内决策", "确定性门禁与回退机制"),
        ("02", "扫描器结果驱动的循环编排", "前序结果决定下一步"),
        ("03", "Finding 指纹与证据哈希", "结果可复核、可追踪"),
        ("04", "失败局部化与断点恢复", "长扫描任务可继续"),
    ]
    app = [
        ("01", "多引擎结果统一呈现", "降低工具切换成本"),
        ("02", "执行数据流按需出现", "不再堆叠 19 张卡片"),
        ("03", "风险组与处置剧本", "面向修复而非只列告警"),
        ("04", "可替换模型的 AI 接入", "云端 / 本地兼容接口"),
    ]
    draw_text(draw, (470, 210), "技术创新", font(30, True), BLUE)
    draw_text(draw, (1330, 210), "应用创新", font(30, True), TEAL)
    for index, (num, title, body) in enumerate(tech):
        top = 270 + index * 165
        box(draw, (100, top, 830, top + 130), title, body, WHITE, LINE, NAVY, MUTED, 24, 18, num)
    for index, (num, title, body) in enumerate(app):
        top = 270 + index * 165
        box(draw, (970, top, 1700, top + 130), title, body, GREEN_LIGHT, "9BCBBE", NAVY, MUTED, 24, 18, num)
    return save(image, "09-innovation.png")


def set_cell_shading(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:fill"), fill)
    tc_pr.append(shading)


def set_cell_margins(cell, top=90, start=110, bottom=90, end=110) -> None:
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


def set_table_borders(table, color="D9D9D9", size="4") -> None:
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


def add_page_number(paragraph) -> None:
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instruction = OxmlElement("w:instrText")
    instruction.set(qn("xml:space"), "preserve")
    instruction.text = " PAGE "
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.append(begin)
    run._r.append(instruction)
    run._r.append(end)


def configure(doc: Document) -> None:
    section = doc.sections[0]
    section.page_width = Cm(21.0)
    section.page_height = Cm(29.7)
    section.top_margin = Cm(1.7)
    section.bottom_margin = Cm(1.6)
    section.left_margin = Cm(1.9)
    section.right_margin = Cm(1.9)
    normal = doc.styles["Normal"]
    normal.font.name = "Microsoft YaHei"
    normal._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
    normal.font.size = Pt(10.5)
    normal.font.color.rgb = RGBColor(0, 0, 0)
    normal.paragraph_format.line_spacing = 1.28
    normal.paragraph_format.space_after = Pt(4)
    for name, size, before, after in (
        ("Title", 28, 0, 10),
        ("Heading 1", 17, 10, 5),
        ("Heading 2", 13, 8, 3),
        ("Heading 3", 11.5, 6, 2),
    ):
        style = doc.styles[name]
        style.font.name = "Microsoft YaHei"
        style._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = RGBColor(0, 0, 0)
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)
        style.paragraph_format.keep_with_next = True
        if name == "Title":
            p_pr = style._element.get_or_add_pPr()
            border = p_pr.find(qn("w:pBdr"))
            if border is not None:
                p_pr.remove(border)
    footer = section.footer.paragraphs[0]
    footer.add_run("攻击面扫描系统技术文档  |  ")
    footer.runs[-1].font.size = Pt(8)
    footer.runs[-1].font.color.rgb = RGBColor(90, 90, 90)
    add_page_number(footer)


def heading(doc: Document, text: str, level: int = 1) -> None:
    doc.add_heading(text, level=level)


def body(doc: Document, text: str) -> None:
    paragraph = doc.add_paragraph(text)
    paragraph.paragraph_format.first_line_indent = Cm(0.64)


def bullet(doc: Document, text: str) -> None:
    paragraph = doc.add_paragraph(text, style="List Bullet")
    paragraph.paragraph_format.space_after = Pt(2)


def table(doc: Document, rows: list[list[str]], widths: list[float] | None = None) -> None:
    count = len(rows[0])
    widths = widths or [16.8 / count] * count
    tbl = doc.add_table(rows=len(rows), cols=count)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = False
    set_table_borders(tbl)
    for row_index, row in enumerate(rows):
        for column_index, value in enumerate(row):
            cell = tbl.cell(row_index, column_index)
            cell.width = Cm(widths[column_index])
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            set_cell_margins(cell)
            if row_index == 0:
                set_cell_shading(cell, NAVY)
            elif row_index % 2 == 0:
                set_cell_shading(cell, "F2F6FA")
            paragraph = cell.paragraphs[0]
            paragraph.paragraph_format.space_after = Pt(0)
            run = paragraph.add_run(value)
            run.font.name = "Microsoft YaHei"
            run._element.rPr.rFonts.set(qn("w:eastAsia"), "Microsoft YaHei")
            run.font.size = Pt(8.2 if row_index else 8.5)
            if row_index == 0:
                run.bold = True
                run.font.color.rgb = RGBColor(255, 255, 255)
    doc.add_paragraph().paragraph_format.space_after = Pt(0)


def image_with_caption(doc: Document, path: Path, caption: str, width: float = 16.2) -> None:
    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    paragraph.paragraph_format.keep_with_next = True
    paragraph.add_run().add_picture(str(path), width=Cm(width))
    cap = doc.add_paragraph()
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cap.paragraph_format.space_after = Pt(8)
    run = cap.add_run(caption)
    run.font.size = Pt(8.5)
    run.font.color.rgb = RGBColor(85, 85, 85)


def page_break(doc: Document) -> None:
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def build_document(images: dict[str, Path]) -> None:
    doc = Document()
    configure(doc)

    # Cover
    cover = doc.add_paragraph()
    cover.paragraph_format.space_before = Pt(72)
    cover.paragraph_format.space_after = Pt(18)
    run = cover.add_run("TECHNICAL DOCUMENT  /  2026")
    run.font.name = "Microsoft YaHei"
    run.font.size = Pt(10)
    run.font.bold = True
    run.font.color.rgb = RGBColor.from_string(BLUE)

    title = doc.add_paragraph(style="Title")
    title.add_run("Attack Surface Scanner")
    title_border = title._p.get_or_add_pPr().find(qn("w:pBdr"))
    if title_border is not None:
        title._p.get_or_add_pPr().remove(title_border)
    subtitle = doc.add_paragraph()
    subtitle.paragraph_format.space_after = Pt(26)
    run = subtitle.add_run("攻击面侦察与漏洞定位系统\n技术文档")
    run.font.size = Pt(23)
    run.font.bold = True

    body(
        doc,
        "面向明确授权资产的多引擎扫描、AI 动态编排、统一证据链与可复核报告系统。",
    )
    table(
        doc,
        [
            ["项目", "内容"],
            ["文档版本", "1.0"],
            ["项目版本", "0.1.0"],
            ["提交日期", "2026-11-10"],
            ["团队", "团队名称 / 学校 / 成员 / 指导教师待填写"],
        ],
        [4.0, 12.4],
    )
    page_break(doc)

    # Contents
    heading(doc, "目录与阅读导航")
    table(
        doc,
        [
            ["章节", "内容", "核心图"],
            ["1", "项目概述与需求分析", "项目定位图"],
            ["2", "系统架构与技术选型", "系统架构图、部署拓扑图"],
            ["3", "端到端数据流", "真实数据流图"],
            ["4", "AI 技术方案", "AI Router 流程图"],
            ["5", "核心功能实现", "数据流与系统截图"],
            ["6", "融合、证据与报告", "多引擎融合图"],
            ["7", "安全设计", "安全门禁图"],
            ["8", "测试、部署与验证实验", "实验路线图"],
            ["9", "创新点、总结与展望", "创新点图"],
        ],
        [1.4, 9.0, 6.0],
    )
    body(
        doc,
        "本版文档按比赛要求压缩到 30 页以内，采用“短文字 + 流程图 + 对照表”的方式，先说明设计结论，再用图展示调用链和验证方法。",
    )
    page_break(doc)

    # 1 Overview
    heading(doc, "1 项目概述")
    body(
        doc,
        "项目面向自有资产或已取得明确授权的测试目标，把子域发现、DNS 解析、HTTP 指纹、端口服务识别、Web 扫描、API 契约检查、前端密钥检查、K8s 基线和主机漏洞扫描统一到一个任务中。",
    )
    body(
        doc,
        "系统不以“列出更多告警”为目标，而是形成可验证的链路：任务授权、动态扫描、Finding 归一化、风险组、证据文件、HTML/JSON 报告和可恢复工作流。",
    )
    table(
        doc,
        [
            ["目标", "实现方式", "结果"],
            ["多工具统一", "Adapter + Finding Schema", "统一字段、来源与严重度"],
            ["流程可视", "LangGraph + SSE + 数据流", "按实际执行顺序出现"],
            ["结果可信", "证据 SHA-256 + 指纹去重", "可下载、可复核"],
            ["AI 可控", "候选工具内选择 + 固定回退", "不生成命令、不越权"],
        ],
        [3.7, 7.0, 6.0],
    )
    image_with_caption(doc, images["overview"], "图 1  项目从问题到输出的总体框架")
    page_break(doc)

    # 2 Requirements
    heading(doc, "2 需求分析")
    body(
        doc,
        "关键约束不是“把所有工具都启动”，而是保证扫描行为在授权边界内可观察、可停止、可恢复，并让结果可以被人类复核。",
    )
    table(
        doc,
        [
            ["需求", "约束", "设计响应"],
            ["合法扫描", "必须有授权与目标范围", "授权门禁、Scope Guard、CIDR 检查"],
            ["长任务", "ZAP/OpenVAS 可能运行很久", "Celery + LangGraph + 预算"],
            ["异构工具", "CLI/REST/GMP 输出不同", "BaseAdapter + 统一解析"],
            ["可恢复", "失败或取消不能全量重跑", "checkpoint + resume_state"],
            ["可复核", "报告不能只有自然语言", "证据文件 + SHA-256"],
            ["模型不确定", "AI 不能决定越权命令", "候选集合 + 白名单 + fallback"],
        ],
        [3.5, 6.4, 6.8],
    )
    image_with_caption(doc, images["requirements"], "图 2  需求约束到设计响应的映射")
    page_break(doc)

    # 3 Architecture
    heading(doc, "3 系统架构设计")
    body(
        doc,
        "系统采用控制面与执行面分离。控制面负责身份、任务和展示，执行面负责 LangGraph、适配器和外部扫描器调用。Worker 不映射宿主机端口，重型工具放在独立容器中。",
    )
    image_with_caption(doc, images["architecture"], "图 3  控制面、编排面与执行面")
    table(
        doc,
        [
            ["层", "技术", "职责"],
            ["前端", "React 18 + Vite + Tailwind CSS", "登录、配置、数据流、报告"],
            ["API", "FastAPI + Pydantic", "JWT、任务 API、SSE"],
            ["编排", "LangGraph + Celery", "状态机、checkpoint、恢复"],
            ["数据", "PostgreSQL + Redis", "任务、证据、快照、队列"],
            ["工具", "固定版本 CLI + ZAP/OpenVAS", "扫描与回调验证"],
        ],
        [2.5, 7.0, 7.2],
    )
    page_break(doc)

    # 4 Deployment
    heading(doc, "4 部署与技术选型")
    body(
        doc,
        "本地优先部署降低了演示和评审环境的依赖。PostgreSQL 保存任务、审计、资产快照和 LangGraph checkpoint；Redis 同时承担 Celery broker 与 SSE 事件总线。",
    )
    image_with_caption(doc, images["deployment"], "图 4  Docker Compose 部署拓扑")
    table(
        doc,
        [
            ["选型", "选择理由", "代价 / 边界"],
            ["FastAPI", "类型校验、SSE、自动 API 文档", "需自行设计任务队列"],
            ["LangGraph", "显式状态、条件边、checkpoint", "学习成本较高"],
            ["PostgreSQL", "关系数据 + JSON + 可靠事务", "本地资源占用较高"],
            ["Redis", "Celery 与实时事件共用", "不是长期事实存储"],
            ["OpenAI 兼容接口", "云端和本地模型均可接入", "模型质量依赖服务"],
        ],
        [3.6, 7.4, 5.7],
    )
    page_break(doc)

    # 5 Data flow
    heading(doc, "5 真实数据流与前端交互")
    body(
        doc,
        "任务详情不再固定排列全部 19 张节点卡片。页面根据 SSE/trace 只显示已经进入执行链的工具，并用箭头表示前序结果交给下一步。未使用工具只保留数量汇总。",
    )
    image_with_caption(doc, images["dataflow"], "图 5  实际执行数据流")
    screenshot = ROOT / "docs" / "project-manual" / "assets" / "ui-adaptive-flow.png"
    if screenshot.exists():
        image_with_caption(doc, screenshot, "图 6  任务详情页：放大的字体、AI 决策标签与纵向数据流", 15.2)
    page_break(doc)

    # 6 AI
    heading(doc, "6 AI 技术方案")
    heading(doc, "6.1 AI 选型理由", 2)
    body(
        doc,
        "AI 采用 OpenAI 兼容的 chat completions 接口，不绑定单一厂商，可接 DeepSeek、其他云端模型或本地兼容服务。这样可以在比赛环境中保持可替换性，并允许关闭 AI 后继续运行确定性流程。",
    )
    body(
        doc,
        "模型只负责“在系统给出的候选扫描器中选下一个”以及后续风险解读，不负责生成扫描命令、决定目标或绕过授权门禁。",
    )
    image_with_caption(doc, images["ai_router"], "图 7  AI 动态编排与确定性回退")
    page_break(doc)

    heading(doc, "6.2 集成方式", 2)
    table(
        doc,
        [
            ["步骤", "代码模块", "行为"],
            ["1", "graph/nodes.py", "生成候选节点，排除已执行和不允许节点"],
            ["2", "ai_service.choose_next_scan_node", "读取前序 Finding、端点和摘要"],
            ["3", "模型请求", "返回 next_node / reason / confidence"],
            ["4", "输出校验", "只接受候选工具或 finish"],
            ["5", "scan_decisions", "持久化决策来源、理由和置信度"],
            ["6", "fallback", "模型失败时按固定安全顺序继续"],
        ],
        [1.5, 7.2, 8.0],
    )
    body(
        doc,
        "LangGraph 的 router 在每次扫描器结束后重新进入，形成“扫描器 -> router -> 下一个扫描器”的循环。scan_decisions 和 checkpoint 共同支持页面展示、报告记录与断点恢复。",
    )
    heading(doc, "6.3 优化策略", 2)
    bullet(doc, "先用确定性规则缩小候选集合，减少模型错误选择的可能。")
    bullet(doc, "用 JSON 结构、候选集合和时间预算限制输出。")
    bullet(doc, "对输入风险摘要和证据样本递归脱敏。")
    bullet(doc, "模型不可用、超时、非法输出或未配置时自动回退固定顺序。")
    bullet(doc, "风险组摘要按批处理并缓存，避免重复请求。")
    page_break(doc)

    # 7 Core
    heading(doc, "7 核心功能实现")
    table(
        doc,
        [
            ["功能", "实现", "结果"],
            ["任务创建", "FastAPI + Pydantic + Guard", "返回 202，Celery 异步执行"],
            ["扫描编排", "LangGraph StateGraph", "节点状态、跳过、恢复"],
            ["工具调用", "BaseAdapter + subprocess/REST/GMP", "超时、取消、范围过滤"],
            ["结果融合", "Finding + 指纹 + 置信度", "去重、来源印证、风险组"],
            ["报告交付", "Jinja2 + JSON + Mermaid", "HTML/JSON/PNG/MMD"],
        ],
        [3.2, 7.2, 6.1],
    )
    image_with_caption(doc, images["core_pipeline"], "图 8  从 API 到报告的核心调用链")
    page_break(doc)

    # 8 Fusion
    heading(doc, "8 多引擎融合与证据链")
    body(
        doc,
        "不同扫描器的原始结果先归一化为统一 Finding，再按 host、port、url、vuln_type 生成指纹。多来源命中保留在 also_reported_by 和证据中，不直接丢弃。",
    )
    image_with_caption(doc, images["fusion"], "图 9  多引擎结果融合与证据交付")
    table(
        doc,
        [
            ["阶段", "输出", "可验证点"],
            ["归一化", "Finding", "字段和严重度一致"],
            ["去重", "唯一指纹", "来源和原始证据保留"],
            ["评分", "confidence", "来源、证据、严重度、暴露度"],
            ["聚合", "Risk Group", "实例数、URL 数、来源"],
            ["证据", "evidence hash", "下载时重新计算 SHA-256"],
        ],
        [2.8, 5.0, 8.6],
    )
    page_break(doc)

    # 9 Security
    heading(doc, "9 安全设计与授权边界")
    body(
        doc,
        "每次任务必须提交授权确认，并经目标主机、scope、DNS 解析、CIDR 和元数据地址检查。重定向、OpenAPI server 和工具输出地址会再次校验，避免扫描器被当作任意网络代理。",
    )
    image_with_caption(doc, images["security"], "图 10  授权与执行安全门禁")
    table(
        doc,
        [
            ["风险", "防护", "剩余边界"],
            ["未授权扫描", "授权确认 / Scope / CIDR", "授权声明需人工保留"],
            ["DNS 重绑定", "解析结果 CIDR 校验", "复杂 DNS 轮换需监控"],
            ["命令注入", "参数列表执行，不使用 shell", "依赖工具自身安全"],
            ["AI 密钥泄露", "Fernet 加密 + 只返回配置状态", "JWT_SECRET 必须保密"],
            ["证据篡改", "SHA-256 校验", "拥有文件写权限者仍可重写"],
        ],
        [3.5, 7.2, 5.7],
    )
    page_break(doc)

    # 10 Testing/deployment
    heading(doc, "10 测试、部署与可重复性")
    body(
        doc,
        "项目提供 Docker Compose 环境、固定工具版本、适配器解析测试、图状态测试、API 安全测试、证据报告测试和靶场验收脚本。",
    )
    table(
        doc,
        [
            ["类别", "当前结果"],
            ["自动化测试", "66 passed, 2 warnings"],
            ["前端生产构建", "通过"],
            ["Python 编译检查", "通过"],
            ["Compose 配置", "基础 profile 与 full profile 通过"],
            ["本地验收", "DVWA / Mock / OpenVAS / 取消恢复 / 报告"],
        ],
        [6.0, 10.7],
    )
    image_with_caption(doc, images["test_pipeline"], "图 11  测试、构建与验收质量门禁")
    page_break(doc)

    # 11 Experiment
    heading(doc, "11 验证实验与替代人工路径")
    body(
        doc,
        "当前系统能证明扫描、融合、证据和报告链路真实可用，但不能仅凭一次成功扫描宣称全面替代人工。后续实验采用人工、单引擎、多引擎、完整 Agent、融合算法和人工复核六组对照。",
    )
    image_with_caption(doc, images["experiment"], "图 12  从基线对照到人机协同的验证路线")
    table(
        doc,
        [
            ["实验阶段", "主要指标", "通过条件"],
            ["实验室等价性", "Recall、Precision、F1、人工耗时", "高危漏报不高于人工"],
            ["融合增益", "去重率、FP Rate、Jaccard", "相对单引擎有显著提升"],
            ["影子运行", "系统独有 / 人工独有 / 共同命中", "真实授权环境中可复核"],
            ["小规模试点", "每资产小时、返工率、满意度", "连续 4-8 周稳定"],
        ],
        [4.0, 7.0, 5.5],
    )
    body(
        doc,
        "系统当前定位为 L2：自动扫描、人工复核与签发。替代人工的合理表述是“替代重复性资产发现、扫描调度、归一化、证据整理和报告草稿”，不替代授权责任、业务逻辑分析和最终签发。",
    )
    page_break(doc)

    # 12 Innovation
    heading(doc, "12 创新点说明")
    image_with_caption(doc, images["innovation"], "图 13  技术创新点与应用创新点")
    table(
        doc,
        [
            ["类型", "创新点", "价值"],
            ["技术", "AI 只在确定性候选工具内选择", "兼顾智能编排与安全边界"],
            ["技术", "扫描器结果驱动下一步", "避免固定流程的无效扫描"],
            ["技术", "Finding 指纹 + 证据哈希", "结果可追踪、可复核"],
            ["技术", "失败局部化 + checkpoint 恢复", "长任务不必全量重跑"],
            ["应用", "任务页按真实数据流展示", "降低阅读与演示成本"],
            ["应用", "风险组 + 处置剧本", "从告警列表转向修复工作流"],
        ],
        [2.0, 7.4, 6.6],
    )
    page_break(doc)

    # 13 Summary
    heading(doc, "13 总结与展望")
    body(
        doc,
        "系统已经形成“授权输入、动态扫描、统一融合、证据留痕、工作流恢复、报告输出”的完整闭环。AI 的引入方式不是替代安全边界，而是在确定性候选空间中优化下一步扫描决策。",
    )
    body(
        doc,
        "下一阶段重点是扩大真实授权目标和人工基线，补充融合算法消融实验，开展影子运行和小规模试点，并将证据保留、审计导出、RBAC 和公网部署安全纳入生产化改造。",
    )
    table(
        doc,
        [
            ["近期", "中期", "长期"],
            ["扩大 ground truth", "加权 / 证据一致性融合", "多租户与组织级审计"],
            ["补充人工基线", "置信度校准", "在线演示与私有化交付"],
            ["影子运行与试点", "模型/本地模型对比", "生产网络与合规运营"],
        ],
        [5.5, 5.5, 5.5],
    )
    page_break(doc)

    # 14 Submission mapping
    heading(doc, "14 大赛提交映射与团队信息")
    table(
        doc,
        [
            ["要求项", "当前材料 / 状态"],
            ["代码仓库", "已有代码、README、.env.example、依赖清单；公开仓库需外部账号"],
            ["Git 历史", "当前工作区未检测到 .git；不能伪造历史，需从已有开发仓库导出"],
            ["README", "项目介绍、架构、安装运行、团队信息模板已补齐"],
            ["演示视频", "已提供 5-8 分钟普通话分镜和讲解稿，待录制"],
            ["技术文档", "本文档，PDF 格式，控制在 30 页以内"],
            ["在线演示", "可选加分项，需公网部署和评审账号"],
        ],
        [4.0, 12.7],
    )
    table(
        doc,
        [
            ["团队信息", "填写内容"],
            ["团队名称", "待填写"],
            ["学校 / 学院", "待填写"],
            ["成员", "待填写"],
            ["指导教师", "待填写"],
            ["评审账号", "待填写（如需要）"],
        ],
        [4.5, 12.2],
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    doc.save(DOCX_PATH)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    images = {
        "overview": diagram_overview(),
        "requirements": diagram_requirements(),
        "architecture": diagram_architecture(),
        "dataflow": diagram_dataflow(),
        "ai_router": diagram_ai_router(),
        "core_pipeline": diagram_core_pipeline(),
        "security": diagram_security(),
        "fusion": diagram_fusion(),
        "deployment": diagram_deployment(),
        "test_pipeline": diagram_test_pipeline(),
        "experiment": diagram_experiment(),
        "innovation": diagram_innovation(),
    }
    build_document(images)
    print(DOCX_PATH)


if __name__ == "__main__":
    main()
