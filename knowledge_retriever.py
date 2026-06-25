from pathlib import Path

KB_DIR = Path(__file__).resolve().parent / "knowledge_base"


def load_knowledge_docs():
    docs = []

    for path in KB_DIR.glob("*.md"):
        docs.append({
            "name": path.name,
            "text": path.read_text(encoding="utf-8")
        })

    return docs


def retrieve_knowledge(query: str, max_docs: int = 3) -> str:
    """
    Simple keyword-based retrieval.
    Upgrade later to embeddings/vector search.
    """
    query_terms = set(query.lower().replace(":", " ").replace("|", " ").split())
    scored = []

    for doc in load_knowledge_docs():
        text = doc["text"].lower()
        score = sum(1 for term in query_terms if term in text)

        if score > 0:
            scored.append((score, doc))

    scored.sort(key=lambda x: x[0], reverse=True)

    selected = scored[:max_docs]

    if not selected:
        return ""

    chunks = []
    for score, doc in selected:
        chunks.append(f"## Source: {doc['name']}\n{doc['text'][:2500]}")

    return "\n\n".join(chunks)