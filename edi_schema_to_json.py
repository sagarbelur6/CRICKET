"""EDI Schema (.txt) to JSON converter.

Reads an EDI schema text that contains:
- INPUT Branching Diagram
- INPUT Record Details

Builds a JSON mapping where each segment key is "SEG___PPPP___Segment" and its
value contains only the fields and composites defined in that segment's Tag block
from Input Record Details.

Key behaviors:
- Segment order/structure comes from Branching Diagram (supports groups/loops)
- Only fields inside official "Tag SEG" blocks are captured (no extra mapping lines)
- Composite elements (e.g., C040) are nested with their subelements
- Positions are normalized to two digits; segment position codes are 4 digits
- Stops Record Details parsing at "Extended Rules"/"Pre-Session"

Usage:
  python edi_schema_to_json.py --input /abs/path/to/schema.txt --output /abs/path/to/edi.json
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union


# ----------------
# Config (placeholders)
# ----------------
DEFAULT_INPUT_SCHEMA_PATH: str = ""
DEFAULT_OUTPUT_JSON_PATH: str = ""


# ----------------
# Logging
# ----------------
LOGGER = logging.getLogger("edi.schema.to.json")
_HANDLER = logging.StreamHandler(stream=sys.stdout)
_FORMATTER = logging.Formatter(
    fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_HANDLER.setFormatter(_FORMATTER)
LOGGER.addHandler(_HANDLER)
LOGGER.setLevel(logging.INFO)


# ----------------
# Data structures
# ----------------
@dataclass
class DiagramNode:
    node_type: str  # "loop" or "segment"
    label: str      # segment code or loop name
    position_code: Optional[str] = None  # e.g., "0500"
    depth: int = 0
    children: List["DiagramNode"] = field(default_factory=list)

    def add_child(self, child: "DiagramNode") -> None:
        self.children.append(child)


@dataclass
class ElementDef:
    element_id: str
    position_within_segment: Optional[str]


@dataclass
class CompositeDef:
    composite_id: str
    position_within_segment: Optional[str]
    subelements: List[ElementDef]


ElementLike = Union[ElementDef, CompositeDef]


class SchemaParserError(Exception):
    pass


class SchemaParser:
    """Parses Branching Diagram and Record Details into structured representations."""

    # Section headers
    RX_BRANCHING_HEADER = re.compile(r"^\s*(?:INPUT\s+)?Branch\w*\s+Diagram\b", re.I)
    RX_DETAILS_HEADER = re.compile(r"^\s*(?:INPUT\s+)?Record\w*\s+Detail\w*\b", re.I)

    # Branching diagram patterns
    RX_SEGMENT_PREFIXED = re.compile(r"^(?P<indent>\s*)Segment\s+(?P<seg>[A-Z0-9]{2,3})(?::\d+)?\*", re.I)
    RX_GROUP_PREFIXED = re.compile(r"^(?P<indent>\s*)Group\s+(?P<group>[A-Z0-9_:\-]+)\*", re.I)

    # Record details patterns
    RX_DETAILS_SEGMENT_HEADER_PREFIXED = re.compile(r"^(?P<indent>\s*)Segment\s+(?P<seg>[A-Z0-9]{2,3})(?::\d+)?\*", re.I)
    RX_DETAILS_SEGMENT_HEADER = re.compile(r"^(?P<seg>[A-Z0-9]{2,3})\b\s*(?:\-|\:|\—|\–)?\s*(?P<name>.+)?$", re.I)
    RX_TAG_LINE = re.compile(r"^\s*Tag\s+(?P<seg>[A-Z0-9]{2,3})\b", re.I)

    RX_ELEMENT_WITH_SEG = re.compile(r"^(?P<indent>\s*)(?P<seg>[A-Z0-9]{2,3})\s*[-* ]\s*(?P<pos>\d{2})\b.*?\b(?P<elem>(?:C\d{2,4})|\d{2,4}|[A-Z0-9]{2,5})\b", re.I)
    RX_ELEMENT_SIMPLE_ID = re.compile(r"^(?P<indent>\s*)(?P<elem>(?:C\d{2,4})|\d{2,4}|[A-Z0-9]{2,5})(?::\d+)?\*", re.I)
    RX_COMPOSITE_SUBELEMENT = re.compile(r"^(?P<indent>\s*)(?P<elem>\d{2,4})(?::(?P<subpos>\d{1,2}))?\*", re.I)

    def __init__(self, text: str) -> None:
        self.text = text

    def parse(self) -> Tuple[List[DiagramNode], Dict[str, List[ElementLike]]]:
        lines = self.text.splitlines()
        diagram_range, details_range = self._locate_sections(lines)
        roots = self._parse_branching_diagram(lines[diagram_range[0]: diagram_range[1]])
        details = self._parse_record_details(lines[details_range[0]: details_range[1]])

        segments_in_order: List[DiagramNode] = []

        def visit(node: DiagramNode) -> None:
            if node.node_type == "segment":
                segments_in_order.append(node)
            for c in node.children:
                visit(c)

        for r in roots:
            visit(r)
        return segments_in_order, details

    def _locate_sections(self, lines: List[str]) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        branching_start = None
        details_start = None
        details_end = None
        for i, line in enumerate(lines):
            if branching_start is None and self.RX_BRANCHING_HEADER.search(line):
                branching_start = i + 1
                continue
            if details_start is None and self.RX_DETAILS_HEADER.search(line):
                details_start = i + 1
                continue
            if details_start is not None and details_end is None:
                if re.search(r"^\s*Extended\s+Rules\b", line, re.I) or re.search(r"^\s*Pre-Session\b", line, re.I):
                    details_end = i
                    break
        if branching_start is None:
            raise SchemaParserError("INPUT Branching Diagram section not found")
        if details_start is None:
            details_start = len(lines)
        if details_end is None:
            details_end = len(lines)
        return (branching_start, details_start - 1), (details_start, details_end)

    def _parse_branching_diagram(self, lines: List[str]) -> List[DiagramNode]:
        roots: List[DiagramNode] = []
        stack: List[DiagramNode] = []
        for raw in lines:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            mseg = self.RX_SEGMENT_PREFIXED.match(line)
            if mseg:
                indent = mseg.group("indent") or ""
                seg = mseg.group("seg").upper()
                depth = self._compute_depth(indent)
                node = DiagramNode(node_type="segment", label=seg, depth=depth)
                self._attach(roots, stack, node)
                continue
            mgrp = self.RX_GROUP_PREFIXED.match(line)
            if mgrp:
                indent = mgrp.group("indent") or ""
                grp = mgrp.group("group")
                depth = self._compute_depth(indent)
                node = DiagramNode(node_type="loop", label=grp, depth=depth)
                self._attach(roots, stack, node)
                continue
        return roots

    def _compute_depth(self, indent: str) -> int:
        cleaned = indent.replace("|", " ").replace("+", " ").replace("-", " ")
        spaces = cleaned.count(" ")
        tabs = cleaned.count("\t")
        return tabs + max(0, spaces // 2)

    def _attach(self, roots: List[DiagramNode], stack: List[DiagramNode], node: DiagramNode) -> None:
        while stack and stack[-1].depth >= node.depth:
            stack.pop()
        if not stack:
            roots.append(node)
        else:
            stack[-1].add_child(node)
        stack.append(node)

    def _parse_record_details(self, lines: List[str]) -> Dict[str, List[ElementLike]]:
        details: Dict[str, List[ElementLike]] = {}
        current_seg: Optional[str] = None
        inside_segment_block = False
        active_tag = False
        pending_composite: Optional[CompositeDef] = None
        composite_indent: Optional[int] = None
        seen_segment_codes: set[str] = set()

        for raw in lines:
            line = raw.rstrip("\n")
            if not line.strip():
                pending_composite = None
                composite_indent = None
                continue

            # Skip mapping arrow lines
            if "----->" in line:
                if active_tag:
                    active_tag = False
                    inside_segment_block = False
                    pending_composite = None
                    composite_indent = None
                continue

            # Segment header lines
            mp = self.RX_DETAILS_SEGMENT_HEADER_PREFIXED.match(line)
            if mp:
                seg = mp.group("seg").upper()
                if seg in seen_segment_codes:
                    current_seg = seg
                    inside_segment_block = False
                    active_tag = False
                    pending_composite = None
                    composite_indent = None
                    continue
                current_seg = seg
                seen_segment_codes.add(seg)
                details.setdefault(current_seg, [])
                inside_segment_block = True
                active_tag = bool(self.RX_TAG_LINE.search(line))
                pending_composite = None
                composite_indent = None
                continue

            mh = self.RX_DETAILS_SEGMENT_HEADER.match(line)
            if mh and len(line.strip().split(" ")[0]) <= 3 and not line.strip().lower().startswith("segment "):
                seg = mh.group("seg").upper()
                if seg in seen_segment_codes:
                    current_seg = seg
                    inside_segment_block = False
                    active_tag = False
                    pending_composite = None
                    composite_indent = None
                    continue
                current_seg = seg
                seen_segment_codes.add(seg)
                details.setdefault(current_seg, [])
                inside_segment_block = True
                active_tag = bool(self.RX_TAG_LINE.search(line))
                pending_composite = None
                composite_indent = None
                continue

            # Tag line
            if inside_segment_block and current_seg and self.RX_TAG_LINE.search(line):
                active_tag = True
                continue

            # Elements only inside Tag block
            if current_seg and active_tag:
                m_el_seg = self.RX_ELEMENT_WITH_SEG.match(line)
                if m_el_seg:
                    indent = m_el_seg.group("indent") or ""
                    pos = m_el_seg.group("pos")
                    elem = m_el_seg.group("elem").upper()
                    if elem.startswith("C") and elem[1:].isdigit():
                        pending_composite = CompositeDef(composite_id=elem, position_within_segment=pos, subelements=[])
                        details[current_seg].append(pending_composite)
                        composite_indent = len(indent)
                        continue
                    if pending_composite is not None and composite_indent is not None:
                        if len(indent) > composite_indent:
                            pending_composite.subelements.append(ElementDef(element_id=elem, position_within_segment=pos))
                            continue
                        else:
                            pending_composite = None
                            composite_indent = None
                    details[current_seg].append(ElementDef(element_id=elem, position_within_segment=pos))
                    continue

                m_simple = self.RX_ELEMENT_SIMPLE_ID.match(line)
                if m_simple:
                    indent = m_simple.group("indent") or ""
                    elem = m_simple.group("elem").upper()
                    if elem.startswith("C") and elem[1:].isdigit():
                        pending_composite = CompositeDef(composite_id=elem, position_within_segment=None, subelements=[])
                        details[current_seg].append(pending_composite)
                        composite_indent = len(indent)
                        continue
                    if pending_composite is not None and composite_indent is not None and len(indent) > composite_indent:
                        pending_composite.subelements.append(ElementDef(element_id=elem, position_within_segment=None))
                        continue
                    details[current_seg].append(ElementDef(element_id=elem, position_within_segment=None))
                    continue

                # composite subelements with explicit :n*
                if pending_composite is not None:
                    m_sub = self.RX_COMPOSITE_SUBELEMENT.match(line)
                    if m_sub:
                        subelem = m_sub.group("elem").upper()
                        subpos = m_sub.group("subpos")
                        pending_composite.subelements.append(ElementDef(element_id=subelem, position_within_segment=subpos))
                        continue

        return details


def build_output_json(
    segments: List[DiagramNode],
    details_map: Dict[str, List[ElementLike]],
) -> Dict[str, Dict[str, Dict[str, str]]]:
    result: Dict[str, Dict[str, Dict[str, str]]] = {}
    seq = 0
    for seg in segments:
        seg_code = seg.label
        pos_code = seg.position_code.zfill(4) if seg.position_code and seg.position_code.isdigit() else None
        if pos_code is None:
            seq += 100
            pos_code = str(seq).zfill(4)
        key = f"{seg_code}___{pos_code}___Segment"
        out: Dict[str, Dict[str, str]] = {}
        ordinal = 0
        for el in details_map.get(seg_code, []):
            if isinstance(el, ElementDef):
                ordinal += 1
                out[f"{el.element_id}_{ordinal}"] = {"value": "", "position": _pos(el.position_within_segment, ordinal)}
            elif isinstance(el, CompositeDef):
                comp: Dict[str, Dict[str, str]] = {}
                subord = 0
                for sub in el.subelements:
                    subord += 1
                    comp[f"{sub.element_id}_{subord}"] = {"value": "", "position": _pos(None, subord)}
                out[el.composite_id] = comp
                ordinal += 1
        result[key] = out
    return result


def _pos(explicit: Optional[str], ordinal: int) -> str:
    if explicit and explicit.isdigit():
        return explicit.zfill(2)
    return str(ordinal).zfill(2)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Parse an EDI schema text file into JSON.")
    parser.add_argument("--input", dest="input_path", type=str, default=DEFAULT_INPUT_SCHEMA_PATH)
    parser.add_argument("--output", dest="output_path", type=str, default=DEFAULT_OUTPUT_JSON_PATH)
    parser.add_argument("--log-level", dest="log_level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]) 
    args = parser.parse_args(argv)

    if not args.input_path:
        LOGGER.error("No input path provided. Set DEFAULT_INPUT_SCHEMA_PATH or pass --input.")
        return 2
    if not args.output_path:
        LOGGER.error("No output path provided. Set DEFAULT_OUTPUT_JSON_PATH or pass --output.")
        return 2

    LOGGER.setLevel(getattr(logging, args.log_level))

    inp = Path(args.input_path)
    outp = Path(args.output_path)
    if not inp.exists() or not inp.is_file():
        LOGGER.error("Input schema file not found: %s", inp)
        return 2

    try:
        text = inp.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        LOGGER.exception("Failed to read input: %s", exc)
        return 1

    try:
        parser_impl = SchemaParser(text)
        segments, details = parser_impl.parse()
        LOGGER.info("Parsed segments: %d", len(segments))
        LOGGER.info("Parsed details for %d segments", len(details))
        edi = build_output_json(segments, details)
    except Exception as exc:
        LOGGER.exception("Parsing failed: %s", exc)
        return 1

    try:
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(json.dumps(edi, indent=2, ensure_ascii=False), encoding="utf-8")
        LOGGER.info("Wrote JSON to: %s", outp)
    except Exception as exc:
        LOGGER.exception("Failed to write JSON: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

