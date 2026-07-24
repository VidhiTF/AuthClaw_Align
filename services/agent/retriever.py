import re

from rag_loader import load_compliance_docs


_QUERY_STOP_WORDS = {
    "a",
    "about",
    "and",
    "are",
    "explain",
    "for",
    "from",
    "in",
    "is",
    "me",
    "of",
    "requirements",
    "show",
    "supporting",
    "the",
    "to",
    "what",
}


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", value.lower())
        if len(token) > 1 and token not in _QUERY_STOP_WORDS
    }


def _excerpt(lines: list[str], match_index: int) -> str:
    start = match_index
    for candidate in range(match_index - 1, max(-1, match_index - 6), -1):
        if lines[candidate].strip().endswith(":"):
            start = candidate
            break
    return "\n".join(lines[start:min(len(lines), match_index + 5)]).strip()


def retrieve_context(query: str) -> str:
    """Return the most relevant checked-in compliance excerpt for a query."""
    normalized_query = " ".join(query.lower().split())
    if not normalized_query:
        return ""

    docs = load_compliance_docs()
    lines = docs.split("\n")

    for i, line in enumerate(lines):
        if normalized_query in line.lower():
            return _excerpt(lines, i)

    query_tokens = _tokens(normalized_query)
    if not query_tokens:
        return ""

    best_index = -1
    best_score = 0
    for i, line in enumerate(lines):
        overlap = query_tokens.intersection(_tokens(line))
        score = len(overlap)
        if score > best_score:
            best_index = i
            best_score = score

    if best_index < 0:
        return ""

    return _excerpt(lines, best_index)
