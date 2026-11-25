const form = document.querySelector("#measurement-form");
const runButton = document.querySelector("#run-button");
const statusBanner = document.querySelector("#measurement-status");
const statusMessage = document.querySelector("#status-message");
const statusTime = document.querySelector("#status-time");
const resultsSection = document.querySelector("#results-section");
const tableBody = document.querySelector("#resource-table-body");
const searchInput = document.querySelector("#resource-search");
const resultFilter = document.querySelector("#result-filter");
const typeFilter = document.querySelector("#type-filter");
const graphSvg = document.querySelector("#dependency-graph");

let activeReport = null;
let activeJob = null;

const modeLabels = { unrestricted: "Unrestricted", ipv4_only: "IPv4-only", ipv6_only: "IPv6-only" };
const capabilityLabels = { ipv4_only: "IPv4-only", dual_stack: "Dual-stack", ipv6_only: "IPv6-only", unknown: "Unknown" };
const connectionOutcomes = {
  address_family_unavailable: "Requested IP family unavailable",
  dns_failure: "DNS resolution failed",
  dns_timeout: "DNS resolution timed out",
  connection_failure: "TCP connection failed",
  connection_timeout: "TCP connection timed out",
};

function setStatus(state, message, time = "") {
  statusBanner.className = `status-banner status-${state}`;
  statusMessage.textContent = message;
  statusTime.textContent = time;
}

function formatTime(dateString) {
  if (!dateString) return "";
  const date = new Date(dateString);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function setExportLinks(jobId) {
  for (const [id, format] of [["download-json", "json"], ["download-csv", "csv"]]) {
    const link = document.getElementById(id);
    link.href = `/api/measurements/${encodeURIComponent(jobId)}/export.${format}`;
    link.classList.remove("disabled-link");
    link.removeAttribute("aria-disabled");
    link.setAttribute("download", `measurement-${jobId}.${format}`);
  }
}

async function pollJob(jobId) {
  while (true) {
    const response = await fetch(`/api/measurements/${encodeURIComponent(jobId)}`);
    const job = await response.json();
    if (!response.ok) throw new Error(job.detail || "Could not read measurement status.");

    if (job.status === "failed") {
      setStatus("failed", job.error || "Measurement failed.", formatTime(job.completed_at));
      throw new Error(job.error || "Measurement failed.");
    }

    if (job.status === "completed") {
      const reportResponse = await fetch(`/api/measurements/${encodeURIComponent(jobId)}/report`);
      const report = await reportResponse.json();
      if (!reportResponse.ok) throw new Error(report.detail || "Measurement report could not be loaded.");
      return { job, report };
    }

    setStatus("running", job.status === "queued" ? "Measurement queued…" : "Chromium is collecting page resources…", "In progress");
    await new Promise((resolve) => window.setTimeout(resolve, 900));
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = document.querySelector("#url-input").value.trim();
  const mode = document.querySelector("#mode-select").value;
  runButton.disabled = true;
  resultsSection.classList.add("hidden");
  setStatus("running", "Starting browser measurement…", "In progress");

  try {
    const response = await fetch("/api/measurements", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, mode }),
    });
    const started = await response.json();
    if (!response.ok) throw new Error(started.detail || "Could not start measurement.");
    activeJob = started.id;
    const { job, report } = await pollJob(activeJob);
    activeReport = report;
    renderReport(report);
    setExportLinks(activeJob);
    setStatus("completed", `Measurement completed — ${report.summary.total_resources} resources observed.`, formatTime(job.completed_at));
  } catch (error) {
    if (statusBanner.classList.contains("status-running")) {
      setStatus("failed", error.message || "Measurement could not be completed.");
    }
  } finally {
    runButton.disabled = false;
  }
});

function renderReport(report) {
  resultsSection.classList.remove("hidden");
  const summary = report.summary || {};
  const resources = report.resources || [];
  const classified = Object.fromEntries(
    ["dns_failure", "connection_failure", "tls_failure", "http_failure", "inconclusive"]
      .map((category) => [category, resources.filter((resource) => resource.failure_classification?.category === category).length]),
  );
  const successCount = resources.filter((resource) => resource.success === true).length;
  const inconclusiveCount = resources.filter((resource) =>
    resource.failure_classification?.category === "inconclusive" || resource.success === null
  ).length;
  const failedCount = resources.filter((resource) =>
    resource.success === false && resource.failure_classification?.category !== "inconclusive"
  ).length;

  document.querySelector("#result-title").textContent = report.target_url || "Measurement results";
  document.querySelector("#result-subtitle").textContent = `${modeLabels[report.measurement_mode] || modeLabels.unrestricted} · ${new Date(report.started_at).toLocaleString()}`;
  document.querySelector("#metric-total").textContent = summary.total_resources ?? resources.length;
  document.querySelector("#metric-success").textContent = successCount;
  document.querySelector("#metric-failed").textContent = failedCount;
  document.querySelector("#metric-inconclusive").textContent = inconclusiveCount;
  document.querySelector("#count-dns").textContent = classified.dns_failure;
  document.querySelector("#count-connection").textContent = classified.connection_failure;
  document.querySelector("#count-tls").textContent = classified.tls_failure;
  document.querySelector("#count-http").textContent = classified.http_failure;
  document.querySelector("#count-inconclusive").textContent = inconclusiveCount;

  populateTypeFilter(resources);
  renderReadiness(report.readiness);
  renderResourceTable();
  renderDependencyGraph(report.dependency_graph || {}, resources);
  renderNetworkEvidence(report.network_mode);
  renderLimitations(report);
}

function renderCapabilityLegend(list, counts = null) {
  list.replaceChildren(...Object.entries(capabilityLabels).map(([capability, label]) => {
    const item = document.createElement("li");
    item.className = `cap-${capability}`;
    item.textContent = counts ? `${label} (${counts[capability]})` : label;
    return item;
  }));
}

function renderReadiness(readiness) {
  const distribution = document.querySelector("#readiness-distribution");
  const legend = document.querySelector("#readiness-counts");
  const total = readiness?.total_baseline_resources;
  const score = (value) => value == null ? "—" : `${value}%`;
  document.querySelector("#dns-readiness").textContent = score(readiness?.dns_ipv6_readiness_percent);
  document.querySelector("#http-readiness").textContent = score(readiness?.http_ipv6_readiness_percent);
  document.querySelector("#baseline-total").textContent = total ?? "—";
  const outcomes = readiness?.http_outcome_counts;
  let status = "Run an unrestricted measurement for this URL to establish the baseline.";
  if (total === 0) {
    status = "The unrestricted run captured no HTTP(S) resources.";
  } else if (total && outcomes) {
    status = `${outcomes.retrieved} retrieved over IPv6 · ${outcomes.failed} failed · ${outcomes.undiscovered} undiscovered · ${outcomes.unverified} unverified`;
  } else if (total) {
    status = "Run IPv6-only for this URL to measure HTTP IPv6 readiness.";
  }
  document.querySelector("#readiness-status").textContent = status;

  legend.hidden = total == null;
  distribution.hidden = !total;
  distribution.replaceChildren();
  if (total == null) return;
  const counts = readiness.dns_counts;
  renderCapabilityLegend(legend, counts);
  if (!total) return;
  for (const [capability, count] of Object.entries(counts)) {
    if (!count) continue;
    const segment = document.createElement("span");
    segment.className = `cap-${capability}`;
    segment.style.flexGrow = count;
    distribution.append(segment);
  }
}

function renderNetworkEvidence(network) {
  const panel = document.querySelector("#network-evidence");
  panel.hidden = !Array.isArray(network?.observed_remote_addresses);
  if (panel.hidden) return;

  const restricted = network.network_enforcement_mechanism === "socks5_ip_family_proxy";
  const peers = network.observed_remote_addresses;
  const families = network.observed_connection_address_families.map((family) => family.replace("ipv", "IPv"));
  const source = restricted ? "Proxy upstream" : "Chromium response";
  document.querySelector("#network-summary").textContent = families.length
    ? `${source} connections observed over ${families.join(" and ")}.`
    : `No ${source.toLowerCase()} peers observed for this measurement.`;

  const peerList = document.querySelector("#network-peers");
  peerList.hidden = peers.length === 0;
  peerList.textContent = peers.map(({ ip, family }) => `${ip} (${family.replace("ipv", "IPv")})`).join(", ");

  const attempts = network.connection_attempts || [];
  const connectionDetails = document.querySelector("#connection-evidence");
  connectionDetails.hidden = attempts.length === 0;
  connectionDetails.open = false;
  document.querySelector("#connection-attempts").replaceChildren(...attempts.map((attempt) => {
    const row = document.createElement("tr");
    const peer = attempt.remote_ip ? `${attempt.remote_ip} (${attempt.upstream_family.replace("ipv", "IPv")})` : "—";
    const outcome = attempt.success ? "Connected" : connectionOutcomes[attempt.failure_reason] || "Failed";
    for (const value of [attempt.hostname, attempt.port, attempt.attempted_ip || "—", peer, outcome]) {
      row.insertCell().textContent = value;
    }
    return row;
  }));
}

function populateTypeFilter(resources) {
  const currentValue = typeFilter.value;
  const types = [...new Set(resources.map((resource) => resource.resource_type).filter(Boolean))].sort();
  typeFilter.replaceChildren(new Option("All resource types", "all"));
  for (const type of types) typeFilter.add(new Option(type, type));
  typeFilter.value = types.includes(currentValue) ? currentValue : "all";
}

function resourceResult(resource) {
  const category = resource.failure_classification?.category;
  if (category === "success" || resource.success === true) return "success";
  if (category === "inconclusive" || resource.success === null) return "inconclusive";
  return "failed";
}

function renderResourceTable() {
  if (!activeReport) return;
  const query = searchInput.value.trim().toLowerCase();
  const resultValue = resultFilter.value;
  const typeValue = typeFilter.value;
  const resources = activeReport.resources || [];
  const visible = resources.map((resource, index) => ({ resource, index })).filter(({ resource }) => {
    const category = resource.failure_classification?.category || "inconclusive";
    const searchable = `${resource.url || ""} ${resource.hostname || ""}`.toLowerCase();
    const matchesQuery = !query || searchable.includes(query);
    const matchesType = typeValue === "all" || resource.resource_type === typeValue;
    const matchesResult = resultValue === "all"
      || (resultValue === "failed" && resourceResult(resource) === "failed")
      || (resultValue === "success" && resourceResult(resource) === "success")
      || (resultValue === "inconclusive" && resourceResult(resource) === "inconclusive")
      || category === resultValue;
    return matchesQuery && matchesType && matchesResult;
  });

  tableBody.replaceChildren();
  document.querySelector("#resource-count-label").textContent = `${visible.length} of ${resources.length} resources`;
  document.querySelector("#table-empty-state").classList.toggle("hidden", visible.length > 0);

  for (const { resource, index } of visible) {
    const row = document.createElement("tr");
    const urlCell = document.createElement("td");
    urlCell.className = "url-cell";
    const url = document.createElement("span");
    url.className = "url-main";
    url.textContent = resource.url || "Unknown URL";
    url.title = resource.url || "";
    const host = document.createElement("span");
    host.className = "url-host";
    host.textContent = resource.hostname || "Hostname unavailable";
    urlCell.append(url, host);
    if (resource.ip_evidence) {
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = "IP details";
      details.append(summary, createIPDetails(resource));
      urlCell.append(details);
    }
    row.append(urlCell);

    const typeCell = document.createElement("td");
    const typeTag = document.createElement("span");
    typeTag.className = "type-tag";
    typeTag.textContent = resource.resource_type || "other";
    typeCell.append(typeTag);
    row.append(typeCell);

    const statusCell = document.createElement("td");
    statusCell.className = "status-code";
    statusCell.textContent = resource.http_status ?? "—";
    row.append(statusCell);

    const resultCell = document.createElement("td");
    const result = resourceResult(resource);
    const badge = document.createElement("span");
    badge.className = `result-badge ${result}`;
    badge.textContent = result === "success" ? "Success" : result === "failed" ? "Failed" : "Inconclusive";
    resultCell.append(badge);
    row.append(resultCell);

    const failureCell = document.createElement("td");
    const failure = resource.failure_classification;
    failureCell.className = failure && failure.category !== "success" ? "failure-label" : "failure-label clear";
    failureCell.textContent = failure && failure.category !== "success" ? failure.category.replaceAll("_", " ") : "—";
    failureCell.title = failure?.reason || "";
    row.append(failureCell);

    row.dataset.resourceIndex = String(index);
    tableBody.append(row);
  }
}

function createIPDetails(resource) {
  const details = document.createElement("dl");
  details.className = "ip-details";
  const { resolved_addresses: resolved, connected_peer: peer, response_peers: peers, proxy_origin: proxy } = resource.ip_evidence || {};
  const formatPeer = ({ ip, family }) => `${ip} (${family.replace("ipv", "IPv")})`;
  const add = (label, value) => {
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    details.append(term, description);
  };
  add("Hostname", resource.hostname || "Unavailable");
  add("DNS capability", capabilityLabels[resource.dns_capability] || capabilityLabels.unknown);
  if (resolved) {
    const sources = { ip_literal: "URL literal", system_getaddrinfo: "System DNS", proxy_getaddrinfo: "Proxy DNS" };
    const missing = resolved.failure_reason ? connectionOutcomes[resolved.failure_reason] || "Lookup incomplete" : "None returned";
    add("Available IPv4", resolved.ipv4.join(", ") || missing);
    add("Available IPv6", resolved.ipv6.join(", ") || missing);
    add("Address source", `${sources[resolved.source]} · hostname`);
  }
  add("Resource peer", peer ? `${formatPeer(peer)} · Chromium response` : "Unavailable");
  if (peers?.length > 1) add("Peers across observed responses", peers.map(formatPeer).join(", "));
  if (proxy) {
    add("Proxy evidence", `${proxy.hostname} · port ${proxy.port} · upstream sockets`);
    add("Attempted IPs", proxy.attempted_addresses.join(", ") || "None recorded");
    add("Connected peers for host and port", proxy.connected_peers.map(formatPeer).join(", ") || "None observed");
  }
  return details;
}

function svgElement(name, attributes = {}) {
  const element = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

function renderDependencyGraph(graph, resources) {
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const knownNodes = nodes.filter((node) => node.depth !== null && node.depth !== undefined);
  const unknownNodes = nodes.filter((node) => node.depth === null || node.depth === undefined);
  renderCapabilityLegend(document.querySelector("#graph-capability-legend"));
  document.querySelector("#graph-count-label").textContent = `${edges.length} relationships`;
  document.querySelector("#graph-empty-state").classList.toggle("hidden", edges.length > 0);
  document.querySelector("#graph-scroll").classList.toggle("hidden", edges.length === 0);
  graphSvg.replaceChildren();
  const nodeDetails = document.querySelector("#graph-node-details");
  nodeDetails.hidden = true;
  nodeDetails.replaceChildren();
  renderUnknownResources(unknownNodes, resources);
  if (edges.length === 0) return;

  const groups = new Map();
  for (const node of knownNodes) {
    if (!groups.has(node.depth)) groups.set(node.depth, []);
    groups.get(node.depth).push(node);
  }
  for (const group of groups.values()) group.sort((a, b) => a.url.localeCompare(b.url));
  const maxDepth = Math.max(...groups.keys());
  const maxRows = Math.max(...[...groups.values()].map((group) => group.length));
  const width = Math.max(640, 220 + (maxDepth + 1) * 250);
  const height = Math.max(190, 50 + maxRows * 76);
  graphSvg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  graphSvg.setAttribute("width", String(width));
  graphSvg.setAttribute("height", String(height));

  const positions = new Map();
  for (const [depth, group] of groups.entries()) {
    const x = 28 + depth * 250;
    const spacing = height / (group.length + 1);
    group.forEach((node, index) => {
      positions.set(node.url, { x, y: spacing * (index + 1) });
    });
  }

  for (const edge of edges) {
    const parent = positions.get(edge.parent_url);
    const child = positions.get(edge.child_url);
    if (!parent || !child) continue;
    graphSvg.append(svgElement("path", {
      d: `M ${parent.x + 190} ${parent.y} C ${parent.x + 220} ${parent.y}, ${child.x - 30} ${child.y}, ${child.x} ${child.y}`,
      class: "graph-edge",
    }));
  }

  const resourceByUrl = new Map(resources.map((resource) => [resource.url, resource]));
  for (const node of knownNodes) {
    const point = positions.get(node.url);
    if (!point) continue;
    const resource = resourceByUrl.get(node.url);
    const capability = resource?.dns_capability || node.dns_capability || "unknown";
    const group = svgElement("g", { role: "button", tabindex: "0", "aria-label": `IP details for ${node.url}` });
    const isRoot = (graph.root_urls || []).includes(node.url);
    group.append(svgElement("rect", {
      x: point.x, y: point.y - 24, width: 190, height: 48, rx: 8,
      class: `graph-node cap-${capability}${isRoot ? " root" : ""}`,
    }));
    const label = svgElement("text", { x: point.x + 11, y: point.y - 3, class: "graph-node-label" });
    const displayUrl = node.url.replace(/^https?:\/\//, "");
    label.textContent = displayUrl.length > 25 ? `${displayUrl.slice(0, 22)}…` : displayUrl;
    const title = svgElement("title");
    title.textContent = `${node.url} · ${capabilityLabels[capability] || capabilityLabels.unknown}`;
    label.append(title);
    group.append(label);
    const type = svgElement("text", { x: point.x + 11, y: point.y + 13, class: "graph-node-type" });
    type.textContent = resource?.resource_type || node.resource_type || "resource";
    group.append(type);
    const showDetails = () => {
      const heading = document.createElement("strong");
      heading.textContent = node.url;
      nodeDetails.replaceChildren(heading, createIPDetails(resource || node));
      nodeDetails.hidden = false;
    };
    group.addEventListener("click", showDetails);
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        showDetails();
      }
    });
    graphSvg.append(group);
  }
}

function renderUnknownResources(nodes, resources) {
  const container = document.querySelector("#unknown-resources");
  container.replaceChildren();
  container.classList.toggle("hidden", nodes.length === 0);
  if (nodes.length === 0) return;
  const heading = document.createElement("strong");
  heading.textContent = `${nodes.length} resource${nodes.length === 1 ? "" : "s"} with unknown dependency: `;
  const details = document.createElement("span");
  const urls = new Map(resources.map((resource) => [resource.url, resource.hostname]));
  details.textContent = nodes.map((node) => urls.get(node.url) || node.url).join(", ");
  container.append(heading, details);
}

function renderLimitations(report) {
  const limitations = [];
  if (report.network_enforcement_mechanism === "socks5_ip_family_proxy") {
    limitations.push("IP-family isolation applies to proxied Chromium TCP web traffic. System DNS and other host traffic are outside this scope.");
  } else if (report.network_enforcement_mechanism === "chromium_disable_ipv6_flag" && report.enforcement_verification_status !== "verified_ipv4_only") {
    limitations.push("This saved report used the earlier IPv4 candidate mode.");
  }
  if (report.nat64_status === "unknown") limitations.push("NAT64/464XLAT status is unknown; observed IPv6 may involve translation.");
  if ((report.resources || []).some((resource) => resource.failure_classification?.category === "inconclusive")) limitations.push("Some resource failures could not be assigned a specific cause.");
  if (!report.navigation?.completed) limitations.push("Navigation did not complete successfully; results may be incomplete.");
  document.querySelector("#limitations-list").replaceChildren(...limitations.map((text) => {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }));
  document.querySelector("#limitations-panel").classList.toggle("hidden", limitations.length === 0);
}

searchInput.addEventListener("input", renderResourceTable);
resultFilter.addEventListener("change", renderResourceTable);
typeFilter.addEventListener("change", renderResourceTable);
