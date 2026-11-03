"""Read a `docker save` image: its layers, the commands that built it, and what
was deleted on the way.

A saved image is a tar holding other tars. Two layouts exist and both are
handled here:

- the **legacy** one: `manifest.json`, one folder per layer with a `layer.tar`
  inside, and a `<digest>.json` configuration file;
- the **OCI** one, which newer Docker and every `buildah`/`podman` write:
  `index.json`, `oci-layout`, and every object - manifests, config, layers -
  under `blobs/sha256/<digest>`.

Why this is a challenge genre of its own: **a Docker image is a stack of
diffs, and a diff cannot remove bytes.** When a Dockerfile does

    COPY secret.txt /app/
    RUN rm /app/secret.txt

the file is still there, in the earlier layer. All the `rm` does is add a marker
to the *next* layer - a file called `.wh.secret.txt` (a "whiteout"), which tells
the union filesystem to hide it. `docker run` shows nothing; the image still
carries every byte. The same goes for a file that a later layer overwrites: both
versions are in the tar.

So this module does three things: it puts the layers back in the order the build
made them, it reads the `history` of the configuration so each layer can be
named by the command that created it, and it reports exactly which files are
hidden or replaced further up - with their contents, because that is the answer.
"""

from __future__ import annotations

import gzip
import json
import zlib
from dataclasses import dataclass, field

from ctfc.core import tarfmt
from ctfc.core.errors import FormatError
from ctfc.core.flags import FlagSet, find_flags

# A whiteout marks a deleted path; the opaque one hides a whole directory.
WHITEOUT_PREFIX = ".wh."
OPAQUE_WHITEOUT = ".wh..wh..opq"
# Reading every byte of every layer of a 2 GB image is not what anyone wants in
# the middle of a CTF, so the listing is bounded.
MAX_LAYER_BYTES = 256 << 20
MAX_MEMBERS = 200_000
# Files this big are not where a flag is hiding; they are not searched.
FLAG_SEARCH_LIMIT = 1 << 20
# A base image rewrites hundreds of its own files; listing them all hides the one
# that matters.
OVERWRITTEN_LIMIT = 40


class DockerError(FormatError):
    """The tar is not a Docker image we can read."""


@dataclass
class LayerFile:
    """One path inside one layer."""

    name: str
    size: int
    kind: str
    layer: int


@dataclass
class Layer:
    """One layer of the image, in build order."""

    index: int
    digest: str  # the file name inside the tar (or the blob digest)
    created_by: str = ""  # the Dockerfile line, from the config's history
    size: int = 0
    files: list[LayerFile] = field(default_factory=list)
    whiteouts: list[str] = field(default_factory=list)  # paths this layer deletes
    notes: list[str] = field(default_factory=list)
    data: bytes = b""  # the layer tar, decompressed if it was gzipped

    @property
    def short(self) -> str:
        return self.digest.replace("blobs/sha256/", "")[:16]


@dataclass
class DeletedFile:
    """A path a later layer hides, but whose bytes are still in the image."""

    name: str
    hidden_by: int  # the layer that whites it out
    present_in: int  # the layer that still holds it
    size: int
    content: bytes | None = None


@dataclass
class DockerReport:
    """What the image is made of, and what it is still carrying."""

    layers: list[Layer] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    config: dict = field(default_factory=dict)
    environment: list[str] = field(default_factory=list)
    entrypoint: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    deleted: list[DeletedFile] = field(default_factory=list)
    overwritten: list[tuple[str, list[int]]] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    oci: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "oci": self.oci,
            "tags": list(self.tags),
            "environment": list(self.environment),
            "entrypoint": list(self.entrypoint),
            "command": list(self.command),
            "layers": [
                {
                    "index": layer.index,
                    "digest": layer.digest,
                    "created_by": layer.created_by,
                    "files": len(layer.files),
                    "whiteouts": list(layer.whiteouts),
                    "size": layer.size,
                    "notes": list(layer.notes),
                }
                for layer in self.layers
            ],
            "deleted": [
                {
                    "name": item.name,
                    "hidden_by": item.hidden_by,
                    "present_in": item.present_in,
                    "size": item.size,
                    "content": None
                    if item.content is None
                    else item.content[:4096].decode("utf-8", "replace"),
                }
                for item in self.deleted
            ],
            "overwritten": [{"name": name, "layers": layers} for name, layers in self.overwritten],
            "flags": list(self.flags),
            "notes": list(self.notes),
        }


def looks_like_image(data: bytes) -> bool:
    """Is this tar a saved Docker image? Its manifest or index gives it away."""
    try:
        entries, _end = tarfmt.read_entries(data)
    except tarfmt.TarError:
        return False
    names = {entry.name.lstrip("./") for entry in entries}
    return bool(names & {"manifest.json", "index.json", "oci-layout", "repositories"})


def _member(data: bytes, entries: list[tarfmt.TarEntry], name: str) -> bytes | None:
    """One member of the outer tar, by name, tolerating the `./` prefix."""
    wanted = name.lstrip("./")
    for entry in entries:
        if entry.name.lstrip("./") == wanted:
            return tarfmt.member(data, entry)
    return None


def _json_member(data: bytes, entries: list[tarfmt.TarEntry], name: str) -> object | None:
    raw = _member(data, entries, name)
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _decompress(blob: bytes) -> bytes:
    """A layer may be a tar, a gzipped tar, or a zstd one (which we cannot read)."""
    if blob[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(blob)
        except (OSError, EOFError, zlib.error) as exc:
            raise DockerError(f"a gzipped layer does not decompress: {exc}") from exc
    if blob[:4] == b"\x28\xb5\x2f\xfd":
        raise DockerError(
            "this layer is zstd-compressed, which the standard library cannot read: "
            "`zstd -d` it first, or `docker save` the image again without zstd"
        )
    return blob


def analyse(data: bytes, flagset: FlagSet | None = None, read_layers: bool = True) -> DockerReport:
    """Read the image: layer order, build history, and the deleted files."""
    try:
        entries, _end = tarfmt.read_entries(data)
    except tarfmt.TarError as exc:
        raise DockerError(f"not a readable tar: {exc}") from exc

    report = DockerReport()
    manifest = _json_member(data, entries, "manifest.json")
    index = _json_member(data, entries, "index.json")
    report.oci = _member(data, entries, "oci-layout") is not None

    layer_names: list[str] = []
    config_name = ""
    if isinstance(manifest, list) and manifest and isinstance(manifest[0], dict):
        first = manifest[0]
        config_name = str(first.get("Config", ""))
        layer_names = [str(name) for name in first.get("Layers", []) if isinstance(name, str)]
        report.tags = [str(tag) for tag in first.get("RepoTags") or [] if isinstance(tag, str)]
    if not layer_names and index is not None:
        layer_names, config_name = _from_oci_index(data, entries, index, report)
    if not layer_names:
        # Last resort: every `*/layer.tar` in the tar, in the order they appear.
        layer_names = [
            entry.name.lstrip("./")
            for entry in entries
            if entry.name.endswith("layer.tar") and entry.is_file
        ]
        if layer_names:
            report.notes.append(
                "no usable manifest: the layers are listed in the order they appear in "
                "the tar, which is usually but not always the build order"
            )
    if not layer_names:
        raise DockerError(
            "no layers found: this tar has no manifest.json, no index.json and no "
            "*/layer.tar, so it is not a saved Docker image"
        )

    _read_config(data, entries, config_name, report)
    for position, name in enumerate(layer_names):
        layer = Layer(index=position, digest=name)
        blob = _member(data, entries, name)
        if blob is None:
            layer.notes.append("the manifest names this layer but the tar does not hold it")
            report.layers.append(layer)
            continue
        layer.size = len(blob)
        if read_layers:
            _read_layer(layer, blob)
        report.layers.append(layer)

    _match_history(report)
    _find_deleted(report, flagset)
    return report


def _from_oci_index(
    data: bytes, entries: list[tarfmt.TarEntry], index: object, report: DockerReport
) -> tuple[list[str], str]:
    """Follow an OCI index to its manifest, then to the layer blobs.

    `index.json` points at a manifest blob, which points at the config blob and
    the layer blobs - all of them under `blobs/sha256/`. One level of
    indirection more than the legacy layout, and nothing else is different.
    """
    if not isinstance(index, dict):
        return [], ""
    manifests = index.get("manifests") or []
    for descriptor in manifests if isinstance(manifests, list) else []:
        if not isinstance(descriptor, dict):
            continue
        digest = str(descriptor.get("digest", "")).replace("sha256:", "")
        annotations = descriptor.get("annotations") or {}
        if isinstance(annotations, dict):
            name = annotations.get("io.containerd.image.name") or annotations.get(
                "org.opencontainers.image.ref.name"
            )
            if isinstance(name, str):
                report.tags.append(name)
        inner = _json_member(data, entries, f"blobs/sha256/{digest}")
        if not isinstance(inner, dict):
            continue
        if isinstance(inner.get("manifests"), list):  # an index of indexes
            continue
        config = inner.get("config") or {}
        config_digest = ""
        if isinstance(config, dict):
            config_digest = str(config.get("digest", "")).replace("sha256:", "")
        layers = []
        for entry in inner.get("layers") or []:
            if isinstance(entry, dict):
                layer_digest = str(entry.get("digest", "")).replace("sha256:", "")
                layers.append(f"blobs/sha256/{layer_digest}")
        if layers:
            return layers, f"blobs/sha256/{config_digest}" if config_digest else ""
    return [], ""


def _read_config(
    data: bytes, entries: list[tarfmt.TarEntry], config_name: str, report: DockerReport
) -> None:
    """The image configuration: the environment, the entrypoint and the history."""
    config = _json_member(data, entries, config_name) if config_name else None
    if not isinstance(config, dict):
        return
    report.config = config
    container = config.get("config") or config.get("Config") or {}
    if isinstance(container, dict):
        report.environment = [
            str(value) for value in container.get("Env") or [] if isinstance(value, str)
        ]
        report.entrypoint = [
            str(value) for value in container.get("Entrypoint") or [] if isinstance(value, str)
        ]
        report.command = [
            str(value) for value in container.get("Cmd") or [] if isinstance(value, str)
        ]


def _match_history(report: DockerReport) -> None:
    """Name each layer with the Dockerfile line that created it.

    The `history` list has one entry per *instruction*, and instructions that
    change no files (ENV, WORKDIR, CMD) are marked `empty_layer`. Dropping those
    lines up lines the rest with the layers, in order.
    """
    history = report.config.get("history") if isinstance(report.config, dict) else None
    if not isinstance(history, list):
        return
    steps = [
        str(step.get("created_by", "")).strip()
        for step in history
        if isinstance(step, dict) and not step.get("empty_layer")
    ]
    for layer, created_by in zip(report.layers, steps, strict=False):
        layer.created_by = created_by
    if len(steps) != len(report.layers):
        report.notes.append(
            f"the configuration lists {len(steps)} non-empty build steps for "
            f"{len(report.layers)} layers: the pairing below may be shifted"
        )


def _read_layer(layer: Layer, blob: bytes) -> None:
    """List one layer's members and note the paths it deletes."""
    try:
        inner = _decompress(blob)
    except DockerError as exc:
        layer.notes.append(str(exc))
        return
    if len(inner) > MAX_LAYER_BYTES:
        layer.notes.append(
            f"the layer is {len(inner)} bytes: only the first {MAX_LAYER_BYTES} are read"
        )
        inner = inner[:MAX_LAYER_BYTES]
    layer.data = inner
    # An instruction like WORKDIR or ENV still produces a layer; its tar is just
    # the two end-of-archive blocks, which is not an error but an empty diff.
    if not inner.strip(b"\x00"):
        layer.notes.append("this layer changes no files (its tar is empty)")
        return
    try:
        members, _end = tarfmt.read_entries(inner)
    except tarfmt.TarError as exc:
        layer.notes.append(f"the layer tar does not read: {exc}")
        return
    for member in members[:MAX_MEMBERS]:
        name = member.name.lstrip("./")
        base = name.rsplit("/", 1)[-1]
        if base == OPAQUE_WHITEOUT:
            layer.whiteouts.append(name[: -len(OPAQUE_WHITEOUT)].rstrip("/") + "/*")
        elif base.startswith(WHITEOUT_PREFIX):
            parent = name[: -len(base)]
            layer.whiteouts.append(parent + base[len(WHITEOUT_PREFIX) :])
        else:
            layer.files.append(
                LayerFile(name=name, size=member.size, kind=member.kind, layer=layer.index)
            )


def _find_deleted(report: DockerReport, flagset: FlagSet | None) -> None:
    """The point of the whole module: what the image still carries but hides.

    A path whited out in layer N is looked for in the layers below; when it is
    found, its bytes are pulled out, because they are the thing that was meant
    to be gone. The same walk finds paths written more than once, where the
    earlier version is equally recoverable.
    """
    holders: dict[str, list[int]] = {}
    files_only: dict[str, list[int]] = {}
    for layer in report.layers:
        for file in layer.files:
            holders.setdefault(file.name, []).append(layer.index)
            if file.kind == "file":
                files_only.setdefault(file.name, []).append(layer.index)

    for layer in report.layers:
        for hidden in layer.whiteouts:
            if hidden.endswith("/*"):
                prefix = hidden[:-1]
                candidates = [name for name in holders if name.startswith(prefix)]
            else:
                candidates = [name for name in holders if name == hidden]
            for name in sorted(candidates):
                sources = [index for index in holders[name] if index < layer.index]
                if not sources:
                    continue
                source = max(sources)
                content = _content_of(report, source, name)
                report.deleted.append(
                    DeletedFile(
                        name=name,
                        hidden_by=layer.index,
                        present_in=source,
                        size=0 if content is None else len(content),
                        content=content,
                    )
                )

    # A path written in several layers keeps every version in the image. Only
    # real files are worth listing: a directory legitimately appears in each
    # layer that touches anything inside it, which would bury the signal.
    replaced = [(name, layers) for name, layers in sorted(files_only.items()) if len(layers) > 1]
    report.overwritten = replaced[:OVERWRITTEN_LIMIT]
    if len(replaced) > OVERWRITTEN_LIMIT:
        report.notes.append(
            f"{len(replaced)} files exist in more than one layer; the first "
            f"{OVERWRITTEN_LIMIT} are listed (a base image rewrites many of its own)"
        )

    searched: list[str] = []
    for item in report.deleted:
        if item.content and len(item.content) <= FLAG_SEARCH_LIMIT:
            searched += [hit.text for hit in find_flags(item.content, flagset)]
    for value in report.environment:
        searched += [hit.text for hit in find_flags(value.encode(), flagset)]
    for layer in report.layers:
        if layer.created_by:
            searched += [hit.text for hit in find_flags(layer.created_by.encode(), flagset)]
    seen: list[str] = []
    for text in searched:
        if text not in seen:
            seen.append(text)
    report.flags = seen


def _content_of(report: DockerReport, layer_index: int, name: str) -> bytes | None:
    """The bytes of one path, out of one layer's tar."""
    for layer in report.layers:
        if layer.index != layer_index or not layer.data:
            continue
        try:
            members, _end = tarfmt.read_entries(layer.data)
        except tarfmt.TarError:
            return None
        for member in members:
            if member.name.lstrip("./") == name and member.is_file:
                return tarfmt.member(layer.data, member)
    return None


def layer_files(report: DockerReport) -> list[LayerFile]:
    """Every file of every layer, flattened, for a caller that wants to extract."""
    out: list[LayerFile] = []
    for layer in report.layers:
        out += layer.files
    return out
