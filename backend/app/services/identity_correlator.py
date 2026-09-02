"""
Identity correlation and campaign attribution.

Maintains both:
1. The original flat case_history list (unchanged behavior/API for
   correlate_email(), so email.py doesn't need to change).
2. A graph representation (NetworkX) where nodes are domains/IPs/URLs/
   case_ids and edges represent co-occurrence -- this enables real
   graph-based queries like "show me every case connected to this
   infrastructure, even indirectly through a chain of shared indicators."
"""

import networkx as nx

case_history = []

# Undirected graph: nodes are typed (domain/ip/url/case), edges connect
# a case to every indicator it contains. Campaign clusters emerge as
# connected components in this graph.
correlation_graph = nx.Graph()


def _add_node_if_missing(graph, node_id, node_type):
    if not graph.has_node(node_id):
        graph.add_node(node_id, type=node_type)


def correlate_email(email_data):
    matches = []

    current_domains = set()
    current_ips = set()
    current_urls = set()

    domain_analysis = email_data.get("domain_analysis", {})

    for key in [
        "sender_domain",
        "reply_to_domain",
        "return_path_domain"
    ]:
        value = domain_analysis.get(key)
        if value:
            current_domains.add(value)

    # FIXED: was "ip_addresses" (key no longer exists) -> "unique_ips"
    for ip in email_data.get("unique_ips", []):
        current_ips.add(ip)

    for url in email_data.get("links", []):
        current_urls.add(url)

    for case in case_history:
        common_domains = current_domains.intersection(case["domains"])
        common_ips = current_ips.intersection(case["ips"])
        common_urls = current_urls.intersection(case["urls"])

        if common_domains or common_ips or common_urls:
            matches.append({
                "case_id": case["case_id"],
                "common_domains": list(common_domains),
                "common_ips": list(common_ips),
                "common_urls": list(common_urls)
            })

    case_id = f"CASE-{len(case_history) + 1:04d}"

    case_history.append({
        "case_id": case_id,
        "domains": current_domains,
        "ips": current_ips,
        "urls": current_urls
    })

    # --- Build graph edges for this case ---
    _add_node_if_missing(correlation_graph, case_id, "case")

    for domain in current_domains:
        _add_node_if_missing(correlation_graph, domain, "domain")
        correlation_graph.add_edge(case_id, domain)

    for ip in current_ips:
        _add_node_if_missing(correlation_graph, ip, "ip")
        correlation_graph.add_edge(case_id, ip)

    for url in current_urls:
        _add_node_if_missing(correlation_graph, url, "url")
        correlation_graph.add_edge(case_id, url)

    return {
        "case_id": case_id,
        "related_cases": matches,
        "correlation_found": len(matches) > 0
    }


def get_campaign_cluster(case_id: str) -> dict | None:
    """
    Returns the full connected component (campaign cluster) containing
    this case -- every case, domain, IP, and URL reachable through any
    chain of shared indicators, not just direct one-hop matches.

    This is the real value graph-based correlation adds over flat
    matching: Case A and Case C might share nothing directly, but if
    Case B shares a domain with A and an IP with C, all three belong
    to the same campaign.
    """
    if case_id not in correlation_graph:
        return None

    component = nx.node_connected_component(correlation_graph, case_id)
    subgraph = correlation_graph.subgraph(component)

    nodes = [
        {"id": n, "type": subgraph.nodes[n].get("type")}
        for n in subgraph.nodes
    ]
    edges = [{"source": u, "target": v} for u, v in subgraph.edges]

    case_nodes = [n["id"] for n in nodes if n["type"] == "case"]

    return {
        "cluster_size": len(case_nodes),
        "case_ids": case_nodes,
        "nodes": nodes,
        "edges": edges,
    }


def get_full_graph() -> dict:
    """Returns the entire correlation graph -- useful for a global
    campaign-overview visualization on the dashboard."""
    nodes = [
        {"id": n, "type": correlation_graph.nodes[n].get("type")}
        for n in correlation_graph.nodes
    ]
    edges = [{"source": u, "target": v} for u, v in correlation_graph.edges]

    return {"nodes": nodes, "edges": edges}