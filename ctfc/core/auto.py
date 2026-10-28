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
the key length test is convincing, to avoid noise). Text that does not read is
also given to the classical solver (Caesar, affine, Atbash, Vigenère, rail
fence), which only reports a decryption that reads clearly better.
"""

from __future__ import annotations

import hashlib
import heapq
from dataclasses import dataclass, field

from ctfc.core import classical, xor
from ctfc.core.budget import Budget
from ctfc.core.codegen import (
    CLASSICAL_OPERATIONS,
    Step,
    chain_cyberchef,
    chain_label,
    chain_snippet,
)
from ctfc.core.encodings import (
    DECODERS,
    DecodeError,
    as_text,
    decode_custom_base64,
    find_custom_alphabet,
)
from ctfc.core.flags import FlagSet
from ctfc.core.magic import match_signature
from ctfc.core.scoring import printable_ratio, score
from ctfc.core.types import Candidate

MIN_SCORE = 0.2  # outputs below this are noise and are not reported
FOUND = 0.9  # a flag in readable text: no need to decode this output further
XOR_MIN_SCORE = 0.6  # an XOR guess must look clearly readable to be kept
# Each of these may appear at most once in a chain, otherwise the search wastes its
# budget on things like rot47 -> rot13 -> rot47, or xor -> xor (two XORs = one XOR).
ONCE_PER_CHAIN = {"rot13", "rot47", "reverse", "xor", "base64_custom"}
CLASSICAL_MIN_SCORE = 0.6  # a classical decryption must read clearly to be kept
CLASSICAL_SECONDS = 3.0  # time given to the classical solver per text node
READS_FINE = 0.8  # text scoring this well is left alone (unless it holds a flag crib)


@dataclass(order=True)
class _Node:
    priority: float  # negative score: heapq pops the smallest first
    order: int  # tie-breaker: older nodes first
    data: bytes = field(compare=False)
    chain: list[Step] = field(compare=False)
    score: float = field(compare=False)
    reasons: list[str] = field(compare=False)


def _decoder_outputs(
    data: bytes,
    chain: list[Step],
    budget: Budget,
    alphabet: str | None = None,
) -> list[tuple[bytes, Step]]:
    """Run every applicable decoder from encodings.py.

    `alphabet`: a shuffled base64 alphabet found in the original input. An
    obfuscator that shuffles the alphabet leaves it in the same file, so trying it
    is free and it is the only way that payload ever decodes.
    """
    used = {step.name for step in chain}
    outputs = []
    if alphabet is not None and "base64_custom" not in used and budget.spend():
        try:
            outputs.append(
                (
                    decode_custom_base64(data, alphabet),
                    Step("base64_custom", {"alphabet": alphabet}),
                )
            )
        except (DecodeError, ValueError, UnicodeError):
            pass
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


def _classical_outputs(
    data: bytes, data_score: float, chain: list[Step], flagset: FlagSet | None, budget: Budget
) -> list[tuple[bytes, Step]]:
    """Best classical decryption of text that does not read (or of a ciphered flag).

    The classical solver gets its own small budget (it tries ~500 keys) so it
    cannot eat the attempts of the decoding search; it shares the cancel button.
    """
    letter_ops = set(CLASSICAL_OPERATIONS) | {"rot13", "rot47"}
    if any(step.name in letter_ops for step in chain) or not classical.is_text_like(data):
        return []
    if data_score >= READS_FINE and not classical.find_cribs(data, flagset):
        return []
    if not budget.spend():
        return []
    own = Budget(max_attempts=2000, max_seconds=CLASSICAL_SECONDS, cancel_event=budget.cancel_event)
    found = classical.solve_classical(data, flagset, budget=own, top_n=1)
    if not found or found[0].score < CLASSICAL_MIN_SCORE or found[0].score <= data_score:
        return []
    return [(found[0].data, Step(**found[0].params["chain"][0]))]


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
    # A shuffled base64 alphabet written in the input is looked for once, and then
    # offered as a decoder at every step of the search.
    found_alphabet = find_custom_alphabet(data)
    alphabet = found_alphabet[0] if found_alphabet else None
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
        outputs = _decoder_outputs(node.data, node.chain, budget, alphabet)
        outputs += _xor_outputs(node.data, node.score, node.chain, flagset, budget)
        outputs += _classical_outputs(node.data, node.score, node.chain, flagset, budget)
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
        return [_with_secrets(_to_candidate(data, root))]
    results.sort(key=lambda item: (-item.score, len(item.chain)))
    return [_with_secrets(_to_candidate(data, item)) for item in results[:top_n]]


def _with_secrets(candidate: Candidate) -> Candidate:
    """Flag credentials written in clear in a decoded config (secrets.find_secrets)."""
    from ctfc.core.secrets import find_secrets

    for secret in find_secrets(candidate.data)[:4]:
        note = f"credential in clear (line {secret.line}): {secret.name} = {secret.value}"
        if secret.rot13:
            note += f" -> ROT13 '{secret.rot13}' (a rotation is mentioned nearby)"
        candidate.reasons.append(note)
    return candidate


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
