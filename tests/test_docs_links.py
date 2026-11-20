"""Automated link, sidebar, CLI command, and MCP tool coverage checks for docs/ Wiki."""

import argparse
import asyncio
import re
from pathlib import Path

from passkey.cli.parser import create_parser
from passkey.mcp_server import mcp

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"

EXPECTED_WIKI_PAGES = (
    "_Sidebar.md",
    "Home.md",
    "01-Quickstart.md",
    "02-Managing-Secrets.md",
    "03-Running-and-Injecting.md",
    "04-AI-Agent-Onboarding.md",
    "05-Team-Workflows.md",
    "06-Security-and-Biometrics.md",
    "07-Browser-Agent-Autofill.md",
    "08-CLI-Command-Reference.md",
    "09-MCP-Tools-and-Prompts-Reference.md",
    "10-Troubleshooting-and-FAQ.md",
)

# Matches standard Markdown links `[label](target)` (excluding images `![alt](src)`)
_MD_LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
_HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)
_FENCED_BLOCK_RE = re.compile(r"```.*?```", re.DOTALL)


def _strip_fenced_code(md_text: str) -> str:
    return _FENCED_BLOCK_RE.sub("", md_text)


def _github_slugify(heading: str) -> str:
    """Approximate GitHub Markdown heading anchor slug generation."""
    cleaned = re.sub(r"`([^`]*)`", r"\1", heading)
    cleaned = re.sub(r"\*+([^*]*)\*+", r"\1", cleaned)
    cleaned = cleaned.strip().lower()
    cleaned = re.sub(r"[^\w\s-]", "", cleaned)
    cleaned = re.sub(r"\s+", "-", cleaned)
    return cleaned


def _extract_heading_slugs(md_path: Path) -> set[str]:
    text = _strip_fenced_code(md_path.read_text(encoding="utf-8"))
    return {_github_slugify(m.group(1)) for m in _HEADING_RE.finditer(text)}


class TestDocsWikiIntegrity:
    """Guarantee Wiki completeness, unbroken relative links, and 100% CLI/MCP coverage."""

    def test_all_expected_wiki_pages_exist_and_are_in_sidebar(self):
        for filename in EXPECTED_WIKI_PAGES:
            page_path = DOCS_DIR / filename
            assert page_path.is_file(), f"Missing expected Wiki page: {page_path}"

        sidebar_text = (DOCS_DIR / "_Sidebar.md").read_text(encoding="utf-8")
        sidebar_targets = {m.group(1) for m in _MD_LINK_RE.finditer(sidebar_text)}

        content_pages = {p for p in EXPECTED_WIKI_PAGES if p != "_Sidebar.md"}
        assert sidebar_targets == content_pages

    def test_all_relative_markdown_links_and_anchors_resolve(self):
        md_files = [REPO_ROOT / "README.md", *(DOCS_DIR / p for p in EXPECTED_WIKI_PAGES)]

        for src_file in md_files:
            content = _strip_fenced_code(src_file.read_text(encoding="utf-8"))
            for match in _MD_LINK_RE.finditer(content):
                raw_target = match.group(1).strip()
                if not raw_target or raw_target.startswith(
                    ("http://", "https://", "mailto:", "file://")
                ):
                    continue

                if "#" in raw_target:
                    rel_part, anchor = raw_target.split("#", 1)
                else:
                    rel_part, anchor = raw_target, ""

                target_path = (
                    (src_file.parent / rel_part).resolve() if rel_part else src_file.resolve()
                )
                assert target_path.exists(), (
                    f"Broken relative link '{raw_target}' in {src_file.relative_to(REPO_ROOT)} "
                    f"(resolved to missing {target_path})"
                )

                if anchor and target_path.suffix.lower() == ".md":
                    slugs = _extract_heading_slugs(target_path)
                    assert anchor.lower() in slugs, (
                        f"Broken heading anchor '#{anchor}' in {src_file.relative_to(REPO_ROOT)} "
                        f"-> {target_path.name} (available: {sorted(slugs)})"
                    )

    def test_every_cli_subcommand_in_parser_is_documented_in_cli_reference(self):
        parser = create_parser()
        subparsers_action = next(
            a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
        )
        all_top_commands = set(subparsers_action.choices.keys())
        assert len(all_top_commands) >= 40

        cli_ref_text = (DOCS_DIR / "08-CLI-Command-Reference.md").read_text(encoding="utf-8")
        for cmd in sorted(all_top_commands):
            pattern = re.compile(
                rf"`passkey\s+(?:\[entry\]\s+|\[mcp\]\s+)?{re.escape(cmd)}\b"
            )
            assert pattern.search(cli_ref_text), (
                f"CLI subcommand '{cmd}' from parser.py is missing from "
                "docs/08-CLI-Command-Reference.md"
            )

    def test_every_mcp_tool_and_prompt_is_documented_in_mcp_reference(self):
        mcp_ref_text = (DOCS_DIR / "09-MCP-Tools-and-Prompts-Reference.md").read_text(
            encoding="utf-8"
        )

        tools = asyncio.run(mcp.list_tools())
        assert len(tools) >= 13
        for tool in tools:
            assert f"`{tool.name}`" in mcp_ref_text, (
                f"MCP tool '{tool.name}' is missing from docs/09-MCP-Tools-and-Prompts-Reference.md"
            )

        prompts = asyncio.run(mcp.list_prompts())
        assert len(prompts) >= 3
        for prompt in prompts:
            assert f"`{prompt.name}`" in mcp_ref_text, (
                f"MCP prompt '{prompt.name}' is missing from "
                "docs/09-MCP-Tools-and-Prompts-Reference.md"
            )

    def test_no_cli_argv_secret_antipattern_in_docs(self):
        """Enforce Landmine #2: never document passing KEY=VALUE or pk1: tokens on passkey CLI argv."""
        bad_argv_re = re.compile(
            r"^\s*passkey\s+(?:new|edit|set-field|add)\s+\S+\s+[A-Z0-9_]+=\S+",
            re.MULTILINE,
        )
        bad_pk1_argv_re = re.compile(
            r"^\s*passkey\s+(?:upload|receive)\s+['\"]?pk1:",
            re.MULTILINE,
        )
        doc_targets = [REPO_ROOT / "README.md", *(DOCS_DIR / p for p in EXPECTED_WIKI_PAGES)]
        for doc_path in doc_targets:
            text = doc_path.read_text(encoding="utf-8")
            rel = doc_path.relative_to(REPO_ROOT)
            assert not bad_argv_re.search(text), (
                f"Found forbidden CLI argv KEY=VALUE example in {rel}"
            )
            assert not bad_pk1_argv_re.search(text), (
                f"Found forbidden CLI argv pk1: token example in {rel}"
            )
