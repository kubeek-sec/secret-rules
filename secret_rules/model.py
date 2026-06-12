"""Unified rule model shared by parsers, the referential builder and generators."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SourceRef:
    """Provenance of a rule: which scanner ruleset it came from."""

    scanner: str  # gitleaks | betterleaks | kingfisher | noseyparker | titus
    id: str  # rule id in that scanner's ruleset

    def to_dict(self) -> dict:
        return {"scanner": self.scanner, "id": self.id}


@dataclass
class Rule:
    """A single secret-detection rule, normalized across scanner formats.

    `pattern` is the canonical (flattened, unnamed-groups) regex produced by
    `normalize.canonicalize`; `secret_group` is the 1-based index of the
    capture group holding the secret (0 = whole match).
    """

    uid: str
    name: str
    topic: str
    pattern: str
    secret_group: int = 0
    secret_group_name: str | None = None  # original named group, if any
    description: str | None = None
    keywords: list[str] = field(default_factory=list)
    entropy: float | None = None
    confidence: str | None = None  # low | medium | high
    categories: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)
    negative_examples: list[str] = field(default_factory=list)
    ignore_if_contains: list[str] = field(default_factory=list)
    allowlist_regexes: list[str] = field(default_factory=list)
    sources: list[SourceRef] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize for the referential YAML, omitting empty fields."""
        d: dict = {
            "uid": self.uid,
            "name": self.name,
            "topic": self.topic,
            "pattern": self.pattern,
            "secret_group": self.secret_group,
        }
        if self.secret_group_name:
            d["secret_group_name"] = self.secret_group_name
        if self.description:
            d["description"] = self.description
        if self.keywords:
            d["keywords"] = self.keywords
        if self.entropy is not None:
            d["entropy"] = self.entropy
        if self.confidence:
            d["confidence"] = self.confidence
        if self.categories:
            d["categories"] = self.categories
        if self.references:
            d["references"] = self.references
        if self.examples:
            d["examples"] = self.examples
        if self.negative_examples:
            d["negative_examples"] = self.negative_examples
        if self.ignore_if_contains:
            d["ignore_if_contains"] = self.ignore_if_contains
        if self.allowlist_regexes:
            d["allowlist_regexes"] = self.allowlist_regexes
        d["sources"] = [s.to_dict() for s in self.sources]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(
            uid=d["uid"],
            name=d["name"],
            topic=d["topic"],
            pattern=d["pattern"],
            secret_group=d.get("secret_group", 0),
            secret_group_name=d.get("secret_group_name"),
            description=d.get("description"),
            keywords=list(d.get("keywords", [])),
            entropy=d.get("entropy"),
            confidence=d.get("confidence"),
            categories=list(d.get("categories", [])),
            references=list(d.get("references", [])),
            examples=list(d.get("examples", [])),
            negative_examples=list(d.get("negative_examples", [])),
            ignore_if_contains=list(d.get("ignore_if_contains", [])),
            allowlist_regexes=list(d.get("allowlist_regexes", [])),
            sources=[SourceRef(**s) for s in d.get("sources", [])],
        )
