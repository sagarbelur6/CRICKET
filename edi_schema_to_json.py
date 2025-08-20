"""EDI Schema (.txt) to JSON converter.

This program reads an EDI schema text file that includes two major sections:
- INPUT Branching Diagram (hierarchical segment/loop structure with segment positions)
- INPUT Record Details (per-segment element definitions, including composites)

It parses both, reconciles segments with their element definitions, and emits a
structured JSON mapping like:

{
  "BNX___0400___Segment": {
    "460_1": {"value": "", "position": "01"},
    "129_2": {"value": "", "position": "02"}
  },
  "N9___0500___Segment": {
    "128_1": {"value": "", "position": "01"},
    "127_2": {"value": "", "position": "02"},
    "C040": {
      "128_1": {"value": "", "position": "01"},
      "127_2": {"value": "", "position": "02"}
    }
  }
}

Notes and assumptions:
- The parser is built with robust heuristics for common EDI schema text formats.
- It supports nested loops and varying indentation levels in the Branching Diagram.
- It supports composite elements (e.g., C040) in Record Details, parsing their
  child subelements and nesting the JSON accordingly.
- Positions within a segment are derived from explicit "-NN" style references
  when present (e.g., SEG-01) or inferred by order as a fallback.
- Segment keys use the format "<SEG>___<position_code>___Segment", where
  <position_code> comes from the Branching Diagram.

You can set input and output paths in the CONFIG section below. Optionally,
command-line arguments --input and --output may override those values.
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


# ============================
# CONFIG (user will edit here)
# ============================

# The user requested placeholders to be set directly in code. Leave these blank.
DEFAULT_INPUT_SCHEMA_PATH: str = ""  # e.g., "/absolute/path/to/schema.txt"
DEFAULT_OUTPUT_JSON_PATH: str = ""   # e.g., "/absolute/path/to/edi.json"


# ===============
# Logging setup
# ===============

LOGGER = logging.getLogger("edi.schema.to.json")
_HANDLER = logging.StreamHandler(stream=sys.stdout)
_FORMATTER = logging.Formatter(
    fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_HANDLER.setFormatter(_FORMATTER)
LOGGER.addHandler(_HANDLER)
LOGGER.setLevel(logging.INFO)


# =====================
# Data model (in-memory)
# =====================


@dataclass
class DiagramNode:
    """Represents a Loop or Segment node from the Branching Diagram."""

    node_type: str  # "loop" or "segment"
    label: str  # e.g., loop name or segment code ("N9")
    position_code: Optional[str] = None  # e.g., "0500" for segments
    depth: int = 0  # indentation depth
    children: List["DiagramNode"] = field(default_factory=list)

    def add_child(self, child: "DiagramNode") -> None:
        self.children.append(child)


@dataclass
class ElementDef:
    """Represents a simple element within a segment (non-composite)."""

    element_id: str  # e.g., "128", "127"
    position_within_segment: Optional[str]  # "01", "02" if present; else None


@dataclass
class CompositeDef:
    """Represents a composite element (e.g., C040) with nested subelements."""

    composite_id: str  # e.g., "C040"
    position_within_segment: Optional[str]  # position of composite within segment
    subelements: List[ElementDef]


ElementLike = Union[ElementDef, CompositeDef]


# ======================
# Parsing implementation
# ======================


class SchemaParserError(Exception):
    pass


class SchemaParser:
    """Parses a schema text into a diagram tree and per-segment element details.

    This parser uses resilient heuristics to handle variations in real-world
    schema text formatting. It reads the full text once, then processes the two
    sections.
    """

    # Section headers (case-insensitive, flexible whitespace)
    RX_BRANCHING_HEADER = re.compile(
        r"^\s*(?:INPUT\s+)?Branch\w*\s+Diagram\b.*$",
        re.I,
    )
    RX_DETAILS_HEADER = re.compile(
        r"^\s*(?:INPUT\s+)?Record\w*\s+Detail\w*\b.*$",
        re.I,
    )

    # Loop recognition in diagram lines
    RX_LOOP = re.compile(r"\bLoop\b\s*:?\s*(?P<loopname>[A-Za-z0-9_\-\/ ]+)?", re.I)

    # Segment recognition in diagram lines. Two common patterns:
    #   1) SEG ... 0500 ... Segment
    #   2) 0500 ... SEG ... Segment
    RX_SEGMENT_A = re.compile(
        r"^(?P<indent>\s*)(?P<seg>[A-Z0-9]{2,3})\b.*?\b(?P<pos>\d{3,4})\b.*?\bSegment\b",
        re.I,
    )
    RX_SEGMENT_B = re.compile(
        r"^(?P<indent>\s*)(?P<pos>\d{3,4})\b.*?\b(?P<seg>[A-Z0-9]{2,3})\b.*?\bSegment\b",
        re.I,
    )
    # Generic: accept any line with a segment code and 3-4 digit position, even if 'Segment' keyword is absent
    RX_SEGMENT_GENERIC = re.compile(
        r"^(?P<indent>[\s\|\+\-\u2500-\u257F]*)(?:(?P<seg>[A-Z0-9]{2,3})\b.*?\b(?P<pos>\d{3,4})\b|(?P<pos2>\d{3,4})\b.*?\b(?P<seg2>[A-Z0-9]{2,3})\b)",
        re.I,
    )
    # Cursor schema style: "Segment N9* ..." without explicit numeric position code
    RX_SEGMENT_PREFIXED = re.compile(
        r"^(?P<indent>\s*)Segment\s+(?P<seg>[A-Z0-9]{2,3})(?::\d+)?\*",
        re.I,
    )
    # Groups act like loops: "Group 1000_N7*" or "Group ST_999:2*"
    RX_GROUP_PREFIXED = re.compile(
        r"^(?P<indent>\s*)Group\s+(?P<group>[A-Z0-9_:\-]+)\*",
        re.I,
    )

    # Record details: segment header lines, e.g., "N9 - Reference Identification"
    RX_DETAILS_SEGMENT_HEADER = re.compile(
        r"^(?P<seg>[A-Z0-9]{2,3})\b\s*(?:\-|\:|\—|\–)?\s*(?P<name>.+)?$",
        re.I,
    )
    RX_DETAILS_SEGMENT_HEADER_PREFIXED = re.compile(
        r"^(?P<indent>\s*)Segment\s+(?P<seg>[A-Z0-9]{2,3})(?::\d+)?\*",
        re.I,
    )
    # Some headers include a following 'Tag <SEG>' line; keep current segment until next Segment line

    # Element lines common patterns:
    #   - N9-01  128  Reference Identification Qualifier
    #   - N9*01*128*...
    #   - 01  128  Reference Identification Qualifier
    # Composite indicator often starts with 'C' followed by digits (e.g., C040)
    RX_ELEMENT_WITH_SEG = re.compile(
        r"^(?P<indent>\s*)(?P<seg>[A-Z0-9]{2,3})\s*[-* ]\s*(?P<pos>\d{2})\b.*?\b(?P<elem>(?:C\d{2,4})|[0-9]{2,4}|[A-Z0-9]{2,5})\b",
        re.I,
    )
    # Cursor schema style element line: starts with element id then '*', e.g., '0128* description'
    RX_ELEMENT_SIMPLE_ID = re.compile(
        r"^(?P<indent>\s*)(?P<elem>(?:C\d{2,4})|\d{2,4}|[A-Z0-9]{2,5})(?::\d+)?\*",
        re.I,
    )
    # Composite subelement lines under a composite: '0128:2* ...'
    RX_COMPOSITE_SUBELEMENT = re.compile(
        r"^(?P<indent>\s*)(?P<elem>\d{2,4})(?::(?P<subpos>\d{1,2}))?\*",
        re.I,
    )

    # Subelement lines beneath a composite often look like:
    #   - 01  128  Reference Identification Qualifier
    #   - 02  127  Reference Identifier
    RX_SUBELEMENT = re.compile(
        r"^(?P<indent>\s*)(?P<subpos>\d{2})\b\s+(?P<subelem>[0-9]{2,4}|[A-Z0-9]{2,5})\b",
        re.I,
    )

    def __init__(self, text: str) -> None:
        self.text = text

    def parse(self) -> Tuple[List[DiagramNode], Dict[str, List[ElementLike]]]:
        """Parse the input text and return (segments_in_order, details_by_segment).

        - segments_in_order: all segment DiagramNodes found in the branching diagram
          (preorder traversal order)
        - details_by_segment: mapping of SEG code -> list[ElementLike]
        """
        lines = self.text.splitlines()
        diagram_range, details_range = self._locate_sections(lines)
        diagram_nodes = self._parse_branching_diagram(lines[diagram_range[0]: diagram_range[1]])
        details_map = self._parse_record_details(lines[details_range[0]: details_range[1]])

        segments_in_order: List[DiagramNode] = []

        def traverse(node: DiagramNode) -> None:
            if node.node_type == "segment":
                segments_in_order.append(node)
            for child in node.children:
                traverse(child)

        for root in diagram_nodes:
            traverse(root)

        return segments_in_order, details_map

    # -------------
    # Section split
    # -------------
    def _locate_sections(self, lines: List[str]) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        branching_start: Optional[int] = None
        details_start: Optional[int] = None

        for idx, line in enumerate(lines):
            if branching_start is None and self.RX_BRANCHING_HEADER.search(line):
                branching_start = idx + 1
                continue
            if details_start is None and self.RX_DETAILS_HEADER.search(line):
                details_start = idx + 1

        if branching_start is None:
            raise SchemaParserError("Could not find 'INPUT Branching Diagram' section header.")
        if details_start is None:
            # If details header missing, assume remainder after branching diagram
            details_start = len(lines)

        branching_end = details_start - 1
        details_end = len(lines)

        return (branching_start, branching_end), (details_start, details_end)

    # --------------------------
    # Branching diagram parsing
    # --------------------------
    def _parse_branching_diagram(self, lines: List[str]) -> List[DiagramNode]:
        roots: List[DiagramNode] = []
        stack: List[DiagramNode] = []

        for raw_line in lines:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue

            # Try segment patterns first
            m = self.RX_SEGMENT_A.match(line) or self.RX_SEGMENT_B.match(line)
            if m:
                indent = m.group("indent") or ""
                seg = m.group("seg").upper()
                pos = m.group("pos")
                depth = self._compute_depth(indent)
                node = DiagramNode(node_type="segment", label=seg, position_code=pos, depth=depth)
                self._attach_node(roots, stack, node)
                LOGGER.debug("Diagram segment: %s %s depth=%d", seg, pos, depth)
                continue

            # Generic segment matcher (no 'Segment' word required)
            mg = self.RX_SEGMENT_GENERIC.match(line)
            if mg:
                indent = mg.group("indent") or ""
                seg = (mg.group("seg") or mg.group("seg2") or "").upper()
                pos = (mg.group("pos") or mg.group("pos2") or "").strip()
                # Sanity checks to reduce false positives
                if seg and pos and len(seg) in (2, 3) and pos.isdigit():
                    depth = self._compute_depth(indent)
                    node = DiagramNode(node_type="segment", label=seg, position_code=pos, depth=depth)
                    self._attach_node(roots, stack, node)
                    LOGGER.debug("Diagram segment (generic): %s %s depth=%d", seg, pos, depth)
                    continue

            # Segment prefixed lines like: "Segment N9* ..."
            mp = self.RX_SEGMENT_PREFIXED.match(line)
            if mp:
                indent = mp.group("indent") or ""
                seg = mp.group("seg").upper()
                depth = self._compute_depth(indent)
                node = DiagramNode(node_type="segment", label=seg, position_code=None, depth=depth)
                self._attach_node(roots, stack, node)
                LOGGER.debug("Diagram segment (prefixed): %s depth=%d", seg, depth)
                continue

            # Group lines act like loop containers
            mgp = self.RX_GROUP_PREFIXED.match(line)
            if mgp:
                indent = mgp.group("indent") or ""
                groupname = mgp.group("group")
                depth = self._compute_depth(indent)
                node = DiagramNode(node_type="loop", label=groupname, position_code=None, depth=depth)
                self._attach_node(roots, stack, node)
                LOGGER.debug("Diagram group/loop: %s depth=%d", groupname, depth)
                continue

            # Loop lines
            if self.RX_LOOP.search(line):
                indent_match = re.match(r"^(\s*)", line)
                indent = indent_match.group(1) if indent_match else ""
                depth = self._compute_depth(indent)
                loopname_match = self.RX_LOOP.search(line)
                loopname = (loopname_match.group("loopname") or "").strip() or "Loop"
                node = DiagramNode(node_type="loop", label=loopname, depth=depth)
                self._attach_node(roots, stack, node)
                LOGGER.debug("Diagram loop: %s depth=%d", loopname, depth)
                continue

            # Ignore unrelated lines in the diagram section
            LOGGER.debug("Ignoring diagram line: %s", line)

        # Fallback: if nothing detected, attempt a full-file tolerant scan
        if not roots:
            LOGGER.warning("No segments detected in Branching Diagram; attempting tolerant scan.")
            for raw_line in lines:
                line = raw_line.rstrip("\n")
                mg = self.RX_SEGMENT_GENERIC.match(line)
                if mg:
                    seg = (mg.group("seg") or mg.group("seg2") or "").upper()
                    pos = (mg.group("pos") or mg.group("pos2") or "").strip()
                    if seg and pos and len(seg) in (2, 3) and pos.isdigit():
                        node = DiagramNode(node_type="segment", label=seg, position_code=pos, depth=0)
                        roots.append(node)
                        LOGGER.debug("Tolerant segment: %s %s", seg, pos)

        return roots

    def _compute_depth(self, indent: str) -> int:
        # Normalize common tree connectors, count spaces/tabs
        # Examples of connectors: |, +, -, ├, └, │, ─
        connector_chars = "|+-\u2500\u2502\u2514\u251C"
        cleaned = indent
        for ch in connector_chars:
            cleaned = cleaned.replace(ch, " ")
        spaces = cleaned.count(" ")
        tabs = cleaned.count("\t")
        return tabs + max(0, spaces // 2)

    def _attach_node(self, roots: List[DiagramNode], stack: List[DiagramNode], node: DiagramNode) -> None:
        # Pop stack until parent with lower depth is found
        while stack and stack[-1].depth >= node.depth:
            stack.pop()

        if not stack:
            roots.append(node)
        else:
            stack[-1].add_child(node)
        stack.append(node)

    # ------------------------
    # Record details parsing
    # ------------------------
    def _parse_record_details(self, lines: List[str]) -> Dict[str, List[ElementLike]]:
        details_map: Dict[str, List[ElementLike]] = {}
        current_seg: Optional[str] = None
        pending_composite: Optional[CompositeDef] = None
        current_indent_for_composite: Optional[int] = None
        inside_segment_block: bool = False
        element_order_by_segment: Dict[str, int] = {}

        for raw_line in lines:
            line = raw_line.rstrip("\n")
            if not line.strip():
                # Blank line resets composite state but keeps current segment
                pending_composite = None
                current_indent_for_composite = None
                continue

            # New segment header
            mp_header = self.RX_DETAILS_SEGMENT_HEADER_PREFIXED.match(line)
            if mp_header:
                current_seg = mp_header.group("seg").upper()
                details_map.setdefault(current_seg, [])
                pending_composite = None
                current_indent_for_composite = None
                inside_segment_block = True
                element_order_by_segment[current_seg] = 0
                LOGGER.debug("Details segment header (prefixed): %s", current_seg)
                continue
            m_header = self.RX_DETAILS_SEGMENT_HEADER.match(line)
            if m_header and len(line.strip().split(" ")[0]) <= 3 and not line.strip().lower().startswith("segment "):
                current_seg = m_header.group("seg").upper()
                details_map.setdefault(current_seg, [])
                pending_composite = None
                current_indent_for_composite = None
                inside_segment_block = True
                element_order_by_segment[current_seg] = 0
                LOGGER.debug("Details segment header: %s", current_seg)
                continue

            # Element line (with or without segment prefix)
            m_element = self.RX_ELEMENT_WITH_SEG.match(line)
            if not m_element:
                m_element = None

            if m_element:
                indent = m_element.group("indent") or ""
                pos = m_element.group("pos")
                elem = m_element.group("elem").upper()

                # If an explicit segment was captured and contradicts current_seg, honor it
                seg_in_line = m_element.groupdict().get("seg")
                if seg_in_line:
                    current_seg = seg_in_line.upper()
                    details_map.setdefault(current_seg, [])
                    pending_composite = None
                    current_indent_for_composite = None

                if current_seg is None:
                    LOGGER.debug("Skipping element line without current segment: %s", line)
                    continue

                if elem.startswith("C") and elem[1:].isdigit():
                    # Start of a composite element
                    pending_composite = CompositeDef(
                        composite_id=elem,
                        position_within_segment=pos,
                        subelements=[],
                    )
                    details_map[current_seg].append(pending_composite)
                    current_indent_for_composite = len(indent)
                    LOGGER.debug("Composite start: %s pos=%s seg=%s", elem, pos, current_seg)
                    continue

                # Simple element
                if pending_composite is not None and current_indent_for_composite is not None:
                    # If indentation suggests continuation under composite, try subelement match
                    if len(indent) > current_indent_for_composite:
                        # treat as subelement of the pending composite
                        pending_composite.subelements.append(
                            ElementDef(element_id=elem, position_within_segment=pos)
                        )
                        LOGGER.debug(
                            "Subelement under %s: %s pos=%s",
                            pending_composite.composite_id,
                            elem,
                            pos,
                        )
                        continue
                    else:
                        # indentation outdented: composite ended
                        pending_composite = None
                        current_indent_for_composite = None

                # normal simple element at segment level
                details_map[current_seg].append(
                    ElementDef(element_id=elem, position_within_segment=pos)
                )
                LOGGER.debug("Element: %s pos=%s seg=%s", elem, pos, current_seg)
                continue

            # If in the middle of a composite, attempt subelement-only match
            if pending_composite is not None:
                m_sub = self.RX_COMPOSITE_SUBELEMENT.match(line)
                if m_sub:
                    subelem = m_sub.group("elem").upper()
                    subpos = m_sub.group("subpos")  # may be None; we'll normalize later
                    pending_composite.subelements.append(
                        ElementDef(element_id=subelem, position_within_segment=subpos)
                    )
                    LOGGER.debug(
                        "Subelement under %s: %s pos=%s",
                        pending_composite.composite_id,
                        subelem,
                        subpos,
                    )
                    continue

            # Elements without explicit segment or position, e.g., '0128* ...' or composite 'C040*'
            if current_seg is not None:
                msimple = self.RX_ELEMENT_SIMPLE_ID.match(line)
                if msimple:
                    indent = msimple.group("indent") or ""
                    elem = msimple.group("elem").upper()

                    # Composite start
                    if elem.startswith("C") and elem[1:].isdigit():
                        pending_composite = CompositeDef(
                            composite_id=elem,
                            position_within_segment=None,
                            subelements=[],
                        )
                        details_map[current_seg].append(pending_composite)
                        current_indent_for_composite = len(indent)
                        LOGGER.debug("Composite start (simple): %s seg=%s", elem, current_seg)
                        continue

                    # If under a composite and indentation suggests subelement but without ':N', treat as subelement without explicit subpos
                    if pending_composite is not None and current_indent_for_composite is not None and len(indent) > current_indent_for_composite:
                        pending_composite.subelements.append(
                            ElementDef(element_id=elem, position_within_segment=None)
                        )
                        LOGGER.debug(
                            "Subelement (indent) under %s: %s",
                            pending_composite.composite_id,
                            elem,
                        )
                        continue

                    # Otherwise, a simple segment-level element
                    details_map[current_seg].append(
                        ElementDef(element_id=elem, position_within_segment=None)
                    )
                    LOGGER.debug("Element (simple): %s seg=%s", elem, current_seg)
                    continue

            # Ignore unrecognized detail lines
            LOGGER.debug("Ignoring detail line: %s", line)

        return details_map


# =========================
# Transformation to JSON
# =========================


def build_output_json(
    segments: List[DiagramNode],
    details_map: Dict[str, List[ElementLike]],
) -> Dict[str, Dict[str, Dict[str, str]]]:
    """Construct the final JSON mapping from parsed structures.

    For each segment in diagram order, build a key "SEG___PPPP___Segment". Its
    value is a mapping of element keys to {"value": "", "position": "NN"}.

    Element keys follow the pattern "<element_id>_<ordinal>". The ordinal is the
    1-based index of the element within the segment (or within the composite when
    nested under a composite). Positions are two-digit strings. Explicit positions
    from the details are used when available; otherwise, they are derived from the
    ordinal order.
    """

    result: Dict[str, Dict[str, Dict[str, str]]] = {}

    # Assign sequential 4-digit position codes if missing: 0100, 0200, ...
    sequential_counter = 0

    for segment_node in segments:
        seg_code = segment_node.label
        if segment_node.position_code and segment_node.position_code.isdigit():
            pos_code = segment_node.position_code.zfill(4)
        else:
            sequential_counter += 100
            pos_code = str(sequential_counter).zfill(4)
        key = f"{seg_code}___{pos_code}___Segment"

        element_entries: Dict[str, Dict[str, str]] = {}
        ordinal_counter = 0

        elements_for_seg = details_map.get(seg_code, [])

        for element_like in elements_for_seg:
            if isinstance(element_like, ElementDef):
                ordinal_counter += 1
                element_key = f"{element_like.element_id}_{ordinal_counter}"
                position = _normalize_position(element_like.position_within_segment, ordinal_counter)
                element_entries[element_key] = {"value": "", "position": position}
            elif isinstance(element_like, CompositeDef):
                # Composite placed at segment level with its id as key
                composite_object: Dict[str, Dict[str, str]] = {}
                subordinal = 0
                for sub in element_like.subelements:
                    subordinal += 1
                    subkey = f"{sub.element_id}_{subordinal}"
                    # For composite subelements, use ordinal-based positions (01, 02, ...)
                    subpos = _normalize_position(None, subordinal)
                    composite_object[subkey] = {"value": "", "position": subpos}

                # Even if no subelements parsed, still include empty composite mapping
                element_entries[element_like.composite_id] = composite_object

                # Maintain the overall ordinal counter for top-level element positions
                ordinal_counter += 1
            else:
                # Defensive: should not happen
                LOGGER.warning("Unknown element type for segment %s: %r", seg_code, element_like)

        result[key] = element_entries

    return result


def _normalize_position(explicit: Optional[str], ordinal: int) -> str:
    if explicit and explicit.isdigit():
        return explicit.zfill(2)
    return str(ordinal).zfill(2)


# ==============
# Main program
# ==============


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Parse an EDI schema text file (branching diagram + record details) into JSON.",
    )
    parser.add_argument("--input", dest="input_path", type=str, default=DEFAULT_INPUT_SCHEMA_PATH,
                        help="Absolute path to the input schema .txt file.")
    parser.add_argument("--output", dest="output_path", type=str, default=DEFAULT_OUTPUT_JSON_PATH,
                        help="Absolute path where edi.json will be written.")
    parser.add_argument("--log-level", dest="log_level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Logging verbosity.")

    args = parser.parse_args(argv)

    # Validate paths: the user prefers to set them in code, but we also allow CLI overrides
    if not args.input_path:
        LOGGER.error("No input path provided. Set DEFAULT_INPUT_SCHEMA_PATH or pass --input.")
        return 2
    if not args.output_path:
        LOGGER.error("No output path provided. Set DEFAULT_OUTPUT_JSON_PATH or pass --output.")
        return 2

    LOGGER.setLevel(getattr(logging, args.log_level))

    input_path = Path(args.input_path)
    output_path = Path(args.output_path)

    if not input_path.exists() or not input_path.is_file():
        LOGGER.error("Input schema file not found: %s", input_path)
        return 2

    try:
        text = input_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        LOGGER.exception("Failed to read input file: %s", exc)
        return 1

    try:
        parser_impl = SchemaParser(text)
        segments_in_order, details_map = parser_impl.parse()
        LOGGER.info("Parsed segments: %d", len(segments_in_order))
        LOGGER.info("Parsed details for %d segments", len(details_map))
        for probe in ("BNX", "N9", "DTM", "BX"):
            if probe in details_map:
                LOGGER.info("Details[%s] elements: %d", probe, len(details_map[probe]))
            else:
                LOGGER.info("Details[%s] not found", probe)
        edi_json = build_output_json(segments_in_order, details_map)
    except SchemaParserError as exc:
        LOGGER.error("Schema parse error: %s", exc)
        return 3
    except Exception as exc:
        LOGGER.exception("Unexpected error while parsing schema: %s", exc)
        return 1

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(edi_json, f, indent=2, ensure_ascii=False)
        LOGGER.info("Wrote JSON to: %s", output_path)
    except Exception as exc:
        LOGGER.exception("Failed to write output JSON: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

