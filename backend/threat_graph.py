import networkx as nx


def build_threat_graph(
    source_ip,
    destination_ip,
    destination_port,
    prediction,
    severity
):
    graph = nx.DiGraph()

    graph.add_node(
        source_ip,
        type="Source"
    )

    graph.add_node(
        destination_ip,
        type="Destination"
    )

    graph.add_node(
        str(destination_port),
        type="Port"
    )

    graph.add_edge(
        source_ip,
        destination_ip,
        relation="CONNECTS_TO"
    )

    graph.add_edge(
        destination_ip,
        str(destination_port),
        relation="USES_PORT"
    )

    if prediction == "ATTACK":
        graph.nodes[source_ip]["threat"] = True
        graph.nodes[destination_ip]["threat"] = True

    return {
        "nodes": [
            {
                "id": node,
                **graph.nodes[node]
            }
            for node in graph.nodes
        ],
        "edges": [
            {
                "source": source,
                "target": target,
                **graph.edges[source, target]
            }
            for source, target in graph.edges
        ],
        "severity": severity,
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges()
    }


if __name__ == "__main__":

    result = build_threat_graph(
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        destination_port=443,
        prediction="ATTACK",
        severity="HIGH"
    )

    print("\n🕸️ SentinelAI Threat Graph")
    print("=" * 50)

    print("Nodes:", result["nodes"])
    print("Edges:", result["edges"])
    print("Severity:", result["severity"])