from retriever import retrieve_context


import time

def rag_node(state):
    print("[RAG Start]", flush=True)
    start_time = time.perf_counter()

    context = retrieve_context(
        state["message"]
    )

    state["context"] = context

    duration = time.perf_counter() - start_time
    print(f"[RAG End] Duration: {duration:.4f}s", flush=True)
    return state