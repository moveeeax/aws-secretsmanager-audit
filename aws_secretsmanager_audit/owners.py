"""Who to page for a secret: an ownership file first, then a tag on the secret itself."""

from __future__ import annotations

import fnmatch
from typing import List, Optional, Sequence, Tuple

from .model import Secret

#: Tag key read when no ownership file entry matches. Looked up exactly first, then
#: case-insensitively, because ``Owner`` and ``owner`` both turn up in real accounts.
DEFAULT_OWNER_TAG = "owner"

OwnerRules = Sequence[Tuple[str, str]]


class OwnersError(ValueError):
    """The ownership file exists but does not say name glob -> owner."""


def load_owners(path: str) -> List[Tuple[str, str]]:
    """Read a YAML (or JSON) mapping of secret-name glob to owner, keeping file order.

    File order matters: the first glob that matches a secret wins, so specific globs go
    above broad ones. PyYAML is imported here so nothing else in the package needs it.
    """
    import yaml

    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise OwnersError("%s is not valid YAML: %s" % (path, exc)) from exc
    if data is None:
        return []
    if not isinstance(data, dict):
        raise OwnersError("%s must be a mapping of secret-name glob to owner" % path)
    rules: List[Tuple[str, str]] = []
    for pattern, owner in data.items():
        if isinstance(owner, (dict, list)) or owner is None or not str(owner).strip():
            raise OwnersError("%s: entry %r needs a single owner value" % (path, pattern))
        if pattern is None or not str(pattern).strip():
            raise OwnersError("%s: an entry has an empty glob" % path)
        rules.append((str(pattern).strip(), str(owner).strip()))
    return rules


def owner_from_tag(secret: Secret, tag: str) -> Optional[str]:
    value = secret.tags.get(tag)
    if value is None:
        wanted = tag.lower()
        for key, candidate in secret.tags.items():
            if key.lower() == wanted:
                value = candidate
                break
    value = (value or "").strip()
    return value or None


def resolve_owner(secret: Secret, rules: OwnerRules, tag: str) -> Optional[str]:
    """The first ownership-file glob matching the name (or the exact ARN), else the tag."""
    for pattern, owner in rules:
        if secret.arn and pattern == secret.arn:
            return owner
        if fnmatch.fnmatchcase(secret.name, pattern):
            return owner
    if tag:
        return owner_from_tag(secret, tag)
    return None
