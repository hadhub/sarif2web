import html
import os
import re

E = html.escape


def _severity_color(level, dark=True):
    if dark:
        return {"error": "#f28b95", "warning": "#f0bc73", "note": "#88baf5", "info": "#88baf5"}.get(level, "#9aaabe")
    return {"error": "#bc3448", "warning": "#9a600a", "note": "#2567af", "info": "#2567af"}.get(level, "#596b80")


def _theme_palette(dark=True):
    if dark:
        return {
            "canvas_bg": "#0e131b",
            "box_bg": "#151c26",
            "box_text": "#e9eef5",
            "box_sub": "#9aaabe",
            "detail_bg": "#19222e",
            "detail_border": "#2b3747",
            "detail_text": "#e9eef5",
            "detail_danger": "#f28b95",
            "file_ref": "#9aaabe",
            "desc_bg": "#151c26",
            "desc_border": "#2b3747",
            "desc_text": "#9aaabe",
            "rule_color": "#73ddbe",
            "source_color": "#73ddbe",
            "sink_color": "#f28b95",
            "step_color": "#88baf5",
        }
    return {
        "canvas_bg": "#f3f6f9",
        "box_bg": "#ffffff",
        "box_text": "#1c2b3e",
        "box_sub": "#596b80",
        "detail_bg": "#f7f9fb",
        "detail_border": "#dce3eb",
        "detail_text": "#1c2b3e",
        "detail_danger": "#bc3448",
        "file_ref": "#596b80",
        "desc_bg": "#ffffff",
        "desc_border": "#dce3eb",
        "desc_text": "#596b80",
        "rule_color": "#087f65",
        "source_color": "#087f65",
        "sink_color": "#bc3448",
        "step_color": "#2567af",
    }


def _cwe_short(cwe_str):
    m = re.match(r"(CWE-\d+)", cwe_str)
    return m.group(1) if m else cwe_str[:20]


def _rule_short_name(rule_id):
    parts = rule_id.split(".")
    return parts[-1] if parts else rule_id


def _wrap_text(text, width=60):
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    out = []
    for raw_line in text.split("\n"):
        line = raw_line
        while len(line) > width:
            idx = line.rfind(" ", 0, width)
            if idx <= 0:
                idx = width
            out.append(line[:idx])
            line = line[idx:].lstrip()
        out.append(line)
    return out[:20]


def render_finding_svg(finding, finding_index=0, dark=True):
    elements = []
    chain_id = f"f{finding_index}"
    pal = _theme_palette(dark)

    CANVAS_W = 1240
    BOX_W = 560
    DETAIL_W = 560
    BOX_H = 80
    GAP_Y = 34
    MARGIN_X = 34
    LEFT_X = MARGIN_X
    RIGHT_X = MARGIN_X + BOX_W + 24
    ARROW_X = LEFT_X + BOX_W // 2

    sev_color = _severity_color(finding["level"], dark)
    cwe_label = ", ".join(_cwe_short(c) for c in finding.get("cwes", [])) if finding.get("cwes") else "N/A"
    locations = finding.get("all_locations", [])
    n_locations = len(locations)

    source_tool = finding.get("source_tool", "")
    tools = finding.get("source_tools") or ([source_tool] if source_tool else [])
    tool_badge = " · " + ", ".join(tools) if tools else ""

    elements.append(f'''
        <defs>
            <marker id="ah-{chain_id}" viewBox="0 0 10 10" refX="9" refY="5"
                    markerWidth="7" markerHeight="5" orient="auto">
                <path d="M0 0 L10 5 L0 10z" fill="{pal['box_sub']}"/>
            </marker>
        </defs>''')

    title_text = finding['rule_id']
    display_title = title_text if len(title_text) <= 100 else title_text[:97] + "..."
    count_text = f"x{n_locations}" if n_locations > 1 else ""

    elements.append(f'''
        <rect x="{MARGIN_X}" y="18" width="{CANVAS_W - MARGIN_X * 2}" height="68" rx="10"
              fill="{pal['box_bg']}" stroke="{pal['detail_border']}"/>
        <text x="{MARGIN_X + 18}" y="42" font-size="11" font-weight="600" fill="{sev_color}">
              {E(finding['level'].upper())}{E(tool_badge)}</text>
        <text x="{MARGIN_X + 18}" y="65" font-size="16" font-weight="600" fill="{pal['box_text']}"><title>{E(title_text)}</title>{E(display_title)}</text>
        <text x="{CANVAS_W - MARGIN_X - 18}" y="42" font-size="12" fill="{pal['box_sub']}" text-anchor="end">
              {E(cwe_label)}  {E(count_text)}</text>''')

    cursor_y = 104

    def _draw_step(label, label_color, title, subtitle, detail_text, file_ref, y):
        parts = []
        detail_lines = _wrap_text(detail_text, 62)
        detail_h = max(BOX_H, len(detail_lines) * 18 + 38)
        row_h = max(BOX_H, detail_h)

        parts.append(f'''
        <g transform="translate({LEFT_X}, {y})">
            <rect width="{BOX_W}" height="{row_h}" rx="10" fill="{pal['box_bg']}"
                  stroke="{pal['detail_border']}"/>
            <rect x="0" y="13" width="3" height="{row_h - 26}" rx="1.5" fill="{label_color}"/>
            <text x="18" y="22" font-size="10" fill="{label_color}"
                  font-weight="600" letter-spacing="1">{E(label)}</text>
            <text x="18" y="45" font-size="15"
                  font-weight="600" fill="{pal['box_text']}"><title>{E(title)}</title>{E(title if len(title) <= 60 else title[:57] + '...')}</text>
            <text x="18" y="65" font-size="12"
                  fill="{pal['box_sub']}" font-family="monospace">{E(subtitle)}</text>
        </g>''')

        parts.append(f'''
        <g transform="translate({RIGHT_X}, {y})">
            <rect width="{DETAIL_W}" height="{row_h}" rx="10" fill="{pal['detail_bg']}"
                  stroke="{pal['detail_border']}" stroke-width="1"/>''')
        for li, line in enumerate(detail_lines):
            clr = pal["detail_danger"] if any(kw in line.lower() for kw in [
                "danger", "vulner", "inject", "unsanit", "malicious",
            ]) else pal["detail_text"]
            parts.append(f'''
            <text x="14" y="{22 + li * 18}" font-size="12" fill="{clr}"
                  font-family="monospace">{E(line)}</text>''')

        file_display = file_ref
        if len(file_display) > 64:
            file_display = "..." + file_display[-61:]
        parts.append(f'''
            <text x="14" y="{row_h - 12}" font-size="11" fill="{pal['file_ref']}"
                  font-family="monospace">{E(file_display)}</text>
        </g>''')

        return "\n".join(parts), row_h

    # RULE step
    rule_svg, rule_h = _draw_step(
        label="RULE", label_color=pal["rule_color"],
        title=_rule_short_name(finding["rule_id"]),
        subtitle=cwe_label,
        detail_text=(finding.get("message") or "")[:250],
        file_ref=finding.get("help_uri") or finding["rule_id"],
        y=cursor_y,
    )
    elements.append(rule_svg)
    cursor_y = cursor_y + rule_h + GAP_Y

    code_flows = finding.get("code_flows", [])

    if code_flows:
        flow = code_flows[0]
        for fi, fstep in enumerate(flow):
            is_first = (fi == 0)
            is_last = (fi == len(flow) - 1)
            label = "SOURCE" if is_first else ("SINK" if is_last else f"STEP {fi}")
            color = pal["source_color"] if is_first else (pal["sink_color"] if is_last else pal["step_color"])

            elements.append(f'''
        <line x1="{ARROW_X}" y1="{cursor_y - GAP_Y + 3}" x2="{ARROW_X}" y2="{cursor_y - 3}"
              stroke="{pal['box_sub']}" stroke-width="1.5" marker-end="url(#ah-{chain_id})"/>''')

            step_svg, step_h = _draw_step(
                label=label, label_color=color,
                title=os.path.basename(fstep["file"]),
                subtitle=f"L{fstep['line']}",
                detail_text=fstep["message"] or fstep["snippet"],
                file_ref=f"{fstep['file']}:{fstep['line']}",
                y=cursor_y,
            )
            elements.append(step_svg)
            cursor_y += step_h + GAP_Y

    elif n_locations <= 3:
        for li, loc in enumerate(locations):
            elements.append(f'''
        <line x1="{ARROW_X}" y1="{cursor_y - GAP_Y + 3}" x2="{ARROW_X}" y2="{cursor_y - 3}"
              stroke="{pal['box_sub']}" stroke-width="1.5" marker-end="url(#ah-{chain_id})"/>''')

            step_svg, step_h = _draw_step(
                label=f"FINDING {li + 1}/{n_locations}" if n_locations > 1 else "FINDING",
                label_color=sev_color,
                title=os.path.basename(loc["file"]),
                subtitle=f"L{loc['start_line']}-L{loc['end_line']}  C{loc.get('start_col', 0)}-C{loc.get('end_col', 0)}",
                detail_text=loc["snippet"],
                file_ref=f"{loc['file']}:{loc['start_line']}",
                y=cursor_y,
            )
            elements.append(step_svg)
            cursor_y += step_h + GAP_Y
    else:
        elements.append(f'''
        <line x1="{ARROW_X}" y1="{cursor_y - GAP_Y + 3}" x2="{ARROW_X}" y2="{cursor_y - 3}"
              stroke="{pal['box_sub']}" stroke-width="1.5" marker-end="url(#ah-{chain_id})"/>''')

        file_list_lines = [f"{loc['file']}:{loc['start_line']}" for loc in locations]
        snippet = locations[0]["snippet"] if locations else ""

        step_svg, step_h = _draw_step(
            label=f"FINDINGS ({n_locations} occurrences)", label_color=sev_color,
            title="Multiple files",
            subtitle=f"{n_locations} locations with same pattern",
            detail_text=snippet + "\n\n" + "\n".join(file_list_lines),
            file_ref=f"{n_locations} files affected",
            y=cursor_y,
        )
        elements.append(step_svg)
        cursor_y += step_h + GAP_Y

    # Description box
    desc = finding.get("description") or finding.get("message") or ""
    if finding.get("help_uri"):
        desc += f"\n\nRef: {finding['help_uri']}"
    if finding.get("tags"):
        desc += f"\nTags: {', '.join(finding['tags'][:10])}"
    desc_lines = _wrap_text(desc, 128)
    desc_h = len(desc_lines) * 18 + 32
    full_w = CANVAS_W - MARGIN_X * 2

    elements.append(f'''
        <g transform="translate({MARGIN_X}, {cursor_y})">
            <rect width="{full_w}" height="{desc_h}" rx="10"
                  fill="{pal['desc_bg']}" stroke="{pal['desc_border']}" stroke-width="1"/>''')
    for li, line in enumerate(desc_lines):
        elements.append(f'''
            <text x="16" y="{24 + li * 18}" font-size="13" fill="{pal['desc_text']}">{E(line)}</text>''')
    elements.append("</g>")

    cursor_y += desc_h + 20

    svg_html = f'''<svg xmlns="http://www.w3.org/2000/svg"
         width="{CANVAS_W + 40}" height="{cursor_y}"
         viewBox="0 0 {CANVAS_W + 40} {cursor_y}" role="img"
         font-family="Inter, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif">
        <title>{E(title_text)}</title>
        <rect width="100%" height="100%" fill="{pal['canvas_bg']}" rx="6"/>
        {"".join(elements)}
    </svg>'''
    return svg_html
