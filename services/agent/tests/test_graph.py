def test_graph_placeholder():
    assert True

if __name__ == "__main__":
    from graph import graph
    result = graph.invoke(
        {
        "message": "What does HIPAA require?"
        }
    )
    print(result)