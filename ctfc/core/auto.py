"""'Magic' mode: peel encoding layers automatically.

Idea (like CyberChef's Magic operation): from the input, try every decoder that
applies, score each output, and keep going on the outputs, most promising first.
Example: "eJwz..." -> base64 -> zlib -> xor(key='k3y') -> "CYBN{...}".

This is a *best-first search*:
- a "node" is (bytes, list of steps applied so far),
- the next node explored is always the best-scoring one not explored yet,
- a node is never explored twice (outputs already seen are skipped),
- the search stops at `max_depth` layers or when the budget runs out.

Besides the encodings, two XOR *solvers* are tried on binary data that is not a
known file or compressed stream: single-byte XOR and repeating-key XOR (only when
the key length test is convincing, to avoid noise).
"""

from __future__ import annotations

import hashlib
import heapq
from dataclasses import dataclass, field

from ctfc.core import xor
from ctfc.core.budget import Budget
from ctfc.core.codegen import Step, chain_cyberchef, chain_label, chain_snippet
from ctfc.core.encodings import DECODERS, DecodeError, as_text
from ctfc.core.flags import FlagSet
from ctfc.core.magic import match_signature
from ctfc.core.scoring import printable_ratio, score
from ctfc.core.types import Candidate

MIN_SCORE = 0.2  # outputs below this are noise and are not reported
FOUND = 0.9  # a flag in readable text: no need to decode this output further
XOR_MIN_SCORE = 0.6  # an XOR guess must look clearly readable to be kept
# Each of these may appear at most once in a chain, otherwise the search wastes its
# budget on things like rot47 -> rot13 -> rot47, or xor -> xor (two XORs = one XOR).
ONCE_PER_CHAIN = {"rot13", "rot47", "reverse", "xor"}


@dataclass(order=True)
class _Node:
    priority: float  # negative score: heapq pops the smallest first
    order: int  # tie-breaker: older nodes first
    data: bytes = field(compare=False)
    chain: list[Step] = field(compare=False)
    score: float = field(compare=False)
    reasons: list[str] = field(compare=False)


def _decoder_outputs(data: bytes, chain: list[Step], budget: Budget) -> list[tuple[bytes, Step]]:
    """Run every applicable decoder from encodings.py."""
    used = {step.name for step in chain}
    outputs = []
    for decoder in DECODERS:
        if decoder.name in ONCE_PER_CHAIN and decoder.name in used:
            continue
        if not decoder.applicable(data):
            continue
        if not budget.spend():
            break
        try:
            outputs.append((decoder.decode(data), Step(decoder.name)))
        except (DecodeError, ValueError, UnicodeError, OverflowError):
            continue
    return outputs


def _xor_worth_trying(data: bytes, data_score: float) -> bool:
    """XOR solvers run on data that is not a known format and does not read well.

    Note: XOR with a small byte (e.g. 0x13) keeps text printable, so printable but
    meaningless text (low score) is tried too.
    """
    if len(data) < 8 or match_signature(data) is not None:
        return False
    if as_text(data) is None and printable_ratio(data)[0] < 0.85:
        return True
    return data_score < 0.6


def _xor_outputs(
    data: bytes, data_score: float, chain: list[Step], flagset: FlagSet | None, budget: Budget
) -> list[tuple[bytes, Step]]:
    """Best single-byte and repeating-key XOR guesses, if they look readable."""
    if any(step.name == "xor" for step in chain) or not _xor_worth_trying(data, data_score):
        return []
    if not budget.spend():
        return []
    candidates = xor.solve_single_byte(data, flagset, top_n=1)
    guesses = xor.guess_key_lengths(data)
    if len(data) >= 32 and xor.lengths_are_convincing(guesses):
        lengths = [g.length for g in guesses[:3]]
        candidates += xor.solve_repeating(data, lengths, flagset, guesses, top_n=1)
    outputs = []
    for candidate in candidates:
        # Keep readable outputs, and also XORs that turn unreadable bytes into fully
        # printable text (scripts, code): a wrong key almost never does that.
        became_printable = (
            len(data) >= 48
            and printable_ratio(data)[0] < 0.85
            and printable_ratio(candidate.data)[0] >= 0.98
        )
        if candidate.score < XOR_MIN_SCORE and not became_printable:
            continue
        step_params = {"key": candidate.params["key_hex"]}
        if "layers" in candidate.params:
            step_params["layers"] = candidate.params["layers"]
        outputs.append((candidate.data, Step("xor", step_params)))
    return outputs


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
        outputs = _decoder_outputs(node.data, node.chain, budget)
        outputs += _xor_outputs(node.data, node.score, node.chain, flagset, budget)
        for output, step in outputs:
            digest = hashlib.sha256(output).digest()
            if not output or digest in seen:
                continue
            seen.add(digest)
            out_score, out_reasons = score(output, flagset)
            counter += 1
            chain = node.chain + [step]
            heapq.heappush(queue, _Node(-out_score, counter, output, chain, out_score, out_reasons))
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
    chain_text = chain_label(node.chain)
    return Candidate(
        label=chain_text,
        data=node.data,
        score=node.score,
        reasons=[f"decoded with {len(node.chain)} layer(s): {chain_text}", *node.reasons],
        params={"chain": [step.to_dict() for step in node.chain]},
        python=chain_snippet(original, node.chain),
        cyberchef=chain_cyberchef(node.chain),
    )
