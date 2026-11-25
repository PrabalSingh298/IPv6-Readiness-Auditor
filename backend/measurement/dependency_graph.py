def build_dependency_graph(resources: list[dict]) -> dict:
    resources_by_url = {resource["url"]: resource for resource in resources}
    edges = []

    for resource in resources:
        dependency = resource.get("dependency", {})
        initiator_url = dependency.get("initiator_url")
        parent_resource = resources_by_url.get(initiator_url)

        if initiator_url and parent_resource and initiator_url != resource["url"]:
            dependency["parent_resource_url"] = initiator_url
            dependency["relationship_status"] = "known"
            edges.append({
                "parent_url": initiator_url,
                "child_url": resource["url"],
                "evidence": "chromium_cdp_initiator",
            })
        else:
            dependency["parent_resource_url"] = None
            if dependency.get("initiator_type") == "other" and resource.get(
                "raw_evidence", {}
            ).get("is_navigation_request"):
                dependency["relationship_status"] = "root"
            elif initiator_url or dependency.get("initiator_type"):
                dependency["relationship_status"] = "unknown"
            else:
                dependency["relationship_status"] = "unavailable"
        dependency["depth"] = None

    roots = [
        resource
        for resource in resources
        if resource.get("dependency", {}).get("relationship_status") == "root"
    ]
    for root in roots:
        root["dependency"]["depth"] = 0

    for _ in range(len(resources)):
        changed = False
        for edge in edges:
            parent = resources_by_url[edge["parent_url"]]
            child = resources_by_url[edge["child_url"]]
            parent_depth = parent["dependency"]["depth"]
            if parent_depth is None:
                continue
            child_depth = parent_depth + 1
            current_depth = child["dependency"]["depth"]
            if current_depth is None or child_depth < current_depth:
                child["dependency"]["depth"] = child_depth
                changed = True
        if not changed:
            break

    return {
        "root_urls": [root["url"] for root in roots],
        "nodes": [
            {
                "url": resource["url"],
                "resource_type": resource.get("resource_type"),
                "depth": resource["dependency"]["depth"],
                "relationship_status": resource["dependency"]["relationship_status"],
            }
            for resource in resources
        ],
        "edges": edges,
    }
