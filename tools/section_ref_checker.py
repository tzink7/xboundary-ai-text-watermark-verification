#!/usr/bin/env python3
"""
section_ref_checker.py

STRUCTURAL check (reliable): does "Section N" refer to a heading that
actually exists in the document? Catches renumbering that leaves a
reference pointing at nothing.

REVIEW AID (not a classifier): for every reference, prints the text
around it side-by-side with the title and opening content of the
section it points to, so you can eyeball a mismatch in a couple of
seconds. An earlier version of this script tried to auto-flag likely
wrong references by keyword overlap between the reference's context
and the target section's title -- it flagged nearly every reference
in a document this size, because a short title like "Record Location
and Syntax" rarely shares vocabulary with an ordinary sentence even
when the reference is correct. That's not a threshold-tuning problem;
it's a sign the signal isn't there. Whether a reference is
semantically right requires actually reading both sides, so that's
what this version is built to make fast, rather than pretending to
decide it for you.

Usage:
    python3 section_ref_checker.py path/to/draft.md
"""

import re
import sys

HEADING_RE = re.compile(r'^#{2,3}\s+(\d+(?:\.\d+)*)\.?\s+(.*)$')
REF_RE = re.compile(r'Section\s+(\d+(?:\.\d+)*)')


def load_sections(text):
    """number -> (title, opening_line_of_body)"""
    lines = text.split('\n')
    sections = {}
    for i, line in enumerate(lines):
        m = HEADING_RE.match(line)
        if not m:
            continue
        num, title = m.group(1).rstrip('.'), m.group(2).strip()
        opener = ''
        for follow in lines[i + 1:]:
            follow = follow.strip()
            if not follow or follow.startswith('#'):
                if opener:
                    break
                if follow.startswith('#'):
                    break
                continue
            opener = follow
            break
        sections[num] = (title, opener[:140])
    return sections


def local_context(text, start, end, radius=90):
    """A character window around the match, not a 'sentence' --
    splitting on '.' breaks on the periods inside '6.1' itself."""
    lo, hi = max(0, start - radius), min(len(text), end + radius)
    snippet = text[lo:hi].replace('\n', ' ')
    return re.sub(r'\s+', ' ', snippet).strip()


def check(path):
    text = open(path, encoding='utf-8').read()
    sections = load_sections(text)
    print(f"Found {len(sections)} numbered headings.\n")

    structural_bad = []
    entries = []

    for m in REF_RE.finditer(text):
        num = m.group(1)
        top = num.split('.')[0]
        context = local_context(text, m.start(), m.end())
        target = sections.get(num) or sections.get(top)

        if target is None:
            structural_bad.append((num, context))
        else:
            entries.append((num, target, context))

    print("=== STRUCTURAL: references to section numbers that don't exist ===")
    print("(these are real bugs -- fix them)\n")
    for num, ctx in structural_bad:
        print(f'  Section {num}: "...{ctx}..."')
    if not structural_bad:
        print("  none")

    print(f"\n=== REVIEW AID: all {len(entries)} references, side by side ===")
    print("(scan the 'points to' column against 'reference says' -- if they")
    print("clearly don't belong together, that's your worklist)\n")
    for num, (title, opener), ctx in entries:
        print(f'  --- Section {num} ---')
        print(f'  reference says : "...{ctx}..."')
        print(f'  points to      : "{title}" -- {opener}')
        print()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 section_ref_checker.py path/to/draft.md")
        sys.exit(1)
    check(sys.argv[1])
