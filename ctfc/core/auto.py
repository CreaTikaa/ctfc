"""'Magic' mode: peel encoding layers automatically.

Idea (like CyberChef's Magic operation): from the input, try every decoder that
applies, score each output, and keep going on the outputs, most promising first.
Example: "eJwz..." -> base64 -> zlib -> hex -> "CYBN{...}".

This is a *best-first search*:
- a "node" is (bytes, list of decoders applied so far),
- the next node explored is always the best-scoring one not explored yet,
- a node is never explored twice (outputs already seen are skipped),
- the search stops at `max_depth` layers or when the budget runs out.
"""

from __future__ import annotations

import hashlib
import heapq
from dataclasses import dataclass, field

from ctfc.core.budget import Budget
from ctfc.core.codegen import chain_cyberchef, chain_snippet
from ctfc.core.encodings import DECODERS, DecodeError
from ctfc.core.flags import FlagSet
from ctfc.core.scoring import score
from ctfc.core.types import Candidate

MIN_SCORE = 0.2  # outputs below this are noise and are not reported
FOUND = 0.97  # a specific flag format matched: no need to decode this output further
# Cosmetic transforms: each may appear at most once in a chain, otherwise the
# search wastes its budget on things like rot47 -> rot13 -> rot47 -> rot13.
ONCE_PER_CHAIN = {"rot13", "rot47", "reverse"}


@dataclass(order=True)
class _Node:
    priority: float  # negative score: heapq pops the smallest first
    order: int  # tie-breaker: older nodes first
    data: bytes = field(compare=False)
    chain: list[str] = field(compare=False)
    score: float = field(compare=False)
    reasons: list[str] = field(compare=False)


def auto_decode(
    data: bytes,
    flagset: FlagSet | None = None,
    max_depth: int = 6,
    budget: Budget | None = None,
    top_n: int = 10,
) -> list[Candidate]:
    """Try decoding chains on `data` and return the best outputs, best first.

    Only outputs that score better than the input itself are reported: if nothing
    beats the input, the list is empty (e.g. ROT13 of a random base64 string).
    """
    budget = budget or Budget(max_attempts=2000, max_seconds=10)
    seen = {hashlib.sha256(data).digest()}
    counter = 0
    root_score, root_reasons = score(data, flagset)
    queue = [_Node(-root_score, counter, data, [], root_score, root_reasons)]
    results: list[_Node] = []

    while queue and not budget.stopped_reason:
        node = heapq.heappop(queue)
        if node.chain:
            results.append(node)
        if len(node.chain) >= max_depth or (node.chain and node.score >= FOUND):
            continue
        for decoder in DECODERS:
            if decoder.name in ONCE_PER_CHAIN and decoder.name in node.chain:
                continue
            if not decoder.applicable(node.data):
                continue
            if not budget.spend():
                break
            try:
                output = decoder.decode(node.data)
            except (DecodeError, ValueError, UnicodeError, OverflowError):
                continue
            digest = hashlib.sha256(output).digest()
            if not output or digest in seen:
                continue
            seen.add(digest)
            out_score, out_reasons = score(output, flagset)
            counter += 1
            heapq.heappush(
                queue,
                _Node(
                    -out_score, counter, output, node.chain + [decoder.name], out_score, out_reasons
                ),
            )
    # Nodes still waiting in the queue were decoded and scored too: report them as well.
    results.extend(item for item in queue if item.chain)

    results = [item for item in results if item.score >= MIN_SCORE and item.score > root_score]
    if not results and root_score >= 0.9:
        # Nothing beats the input because the input itself already holds the answer.
        root = _Node(-root_score, 0, data, [], root_score, root_reasons)
        return [_to_candidate(data, root)]
    results.sort(key=lambda item: (-item.score, len(item.chain)))
    return [_to_candidate(data, item) for item in results[:top_n]]


def _to_candidate(original: bytes, node: _Node) -> Candidate:
    if not node.chain:
        return Candidate(
            label="(input as given)",
            data=node.data,
            score=node.score,
            reasons=["the input itself already looks like the answer", *node.reasons],
        )
    chain_text = " -> ".join(node.chain)
    return Candidate(
        label=chain_text,
        data=node.data,
        score=node.score,
        reasons=[f"decoded with {len(node.chain)} layer(s): {chain_text}", *node.reasons],
        params={"chain": list(node.chain)},
        python=chain_snippet(original, node.chain),
        cyberchef=chain_cyberchef(node.chain),
    )
