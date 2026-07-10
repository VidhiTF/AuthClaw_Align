from rag_loader import load_compliance_docs


def retrieve_context(query):

    docs = load_compliance_docs()

    query = query.lower()

    lines = docs.split("\n")

    for i, line in enumerate(lines):

        if query in line.lower():

            start = max(0, i)
            end = min(len(lines), i + 5)

            return "\n".join(
                lines[start:end]
            )

    return ""