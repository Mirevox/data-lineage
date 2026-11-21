import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import {
  LineageEdgeSchema,
  LineageGraphSnapshotSchema,
  LineageNodeSchema,
  type IngressTag,
  type LineageEdge,
  type LineageGraphSnapshot,
  type LineageNode,
  type ProviderEndpoint,
  type RouteDecision,
} from "../types.js";

/**
 * In-memory egress/lineage graph for AI traffic.
 * Records ingress → policy → provider hops with perimeter flags.
 */
export class LineageGraph {
  private nodes = new Map<string, LineageNode>();
  private edges: LineageEdge[] = [];

  upsertNode(node: LineageNode): LineageNode {
    const parsed = LineageNodeSchema.parse(node);
    this.nodes.set(parsed.id, parsed);
    return parsed;
  }

  addEdge(edge: Omit<LineageEdge, "id"> & { id?: string }): LineageEdge {
    const parsed = LineageEdgeSchema.parse({
      id: edge.id ?? randomUUID(),
      ...edge,
    });
    if (!this.nodes.has(parsed.from) || !this.nodes.has(parsed.to)) {
      throw new Error(
        `Lineage edge ${parsed.id} references missing node(s): ${parsed.from} → ${parsed.to}`,
      );
    }
    this.edges.push(parsed);
    return parsed;
  }

  /**
   * Record a full AI request path: client → ingress → router → policy → provider.
   */
  recordAiHop(input: {
    tag: IngressTag;
    routerId?: string;
    candidate: ProviderEndpoint;
    decision: RouteDecision;
    now?: () => Date;
  }): { nodes: LineageNode[]; edges: LineageEdge[] } {
    const at = (input.now?.() ?? new Date()).toISOString();
    const routerId = input.routerId ?? "router:default";
    const clientId = `client:${input.tag.sourceId}`;
    const ingressId = `ingress:${input.tag.correlationId}`;
    const policyId = `policy:${input.tag.correlationId}`;
    const providerId = `provider:${input.candidate.providerId}:${input.candidate.modelId}`;
    const regionId = `region:${input.candidate.residency}`;

    const nodes = [
      this.upsertNode({
        id: clientId,
        kind: "client",
        label: input.tag.sourceId,
        residency: input.tag.declaredResidency,
        meta: { tenantId: input.tag.tenantId },
      }),
      this.upsertNode({
        id: ingressId,
        kind: "ingress",
        label: "ingress-tag",
        residency: input.tag.declaredResidency,
        meta: {
          correlationId: input.tag.correlationId,
          dataClasses: input.tag.dataClasses,
        },
      }),
      this.upsertNode({
        id: routerId,
        kind: "router",
        label: routerId,
        meta: {},
      }),
      this.upsertNode({
        id: policyId,
        kind: "policy",
        label: input.decision.decision,
        meta: {
          reason: input.decision.reason,
          matchedRuleId: input.decision.matchedRuleId,
        },
      }),
      this.upsertNode({
        id: providerId,
        kind: "provider",
        label: `${input.candidate.providerId}/${input.candidate.modelId}`,
        residency: input.candidate.residency,
        meta: {
          endpoint: input.candidate.endpoint,
          leavesPerimeter: input.candidate.leavesPerimeter,
        },
      }),
      this.upsertNode({
        id: regionId,
        kind: "region",
        label: input.candidate.residency,
        residency: input.candidate.residency,
        meta: {},
      }),
    ];

    const leaves =
      input.decision.decision === "allow" && input.candidate.leavesPerimeter;

    const edges = [
      this.addEdge({
        from: clientId,
        to: ingressId,
        kind: "ingress",
        correlationId: input.tag.correlationId,
        leavesPerimeter: false,
        at,
        meta: {},
      }),
      this.addEdge({
        from: ingressId,
        to: routerId,
        kind: "route",
        correlationId: input.tag.correlationId,
        leavesPerimeter: false,
        at,
        meta: {},
      }),
      this.addEdge({
        from: routerId,
        to: policyId,
        kind: "policy_eval",
        correlationId: input.tag.correlationId,
        leavesPerimeter: false,
        at,
        meta: { decision: input.decision.decision },
      }),
      this.addEdge({
        from: policyId,
        to: providerId,
        kind: "egress",
        correlationId: input.tag.correlationId,
        leavesPerimeter: leaves,
        at,
        meta: {
          decision: input.decision.decision,
          endpoint: input.candidate.endpoint,
        },
      }),
      this.addEdge({
        from: providerId,
        to: regionId,
        kind: "egress",
        correlationId: input.tag.correlationId,
        leavesPerimeter: leaves,
        at,
        meta: {},
      }),
    ];

    return { nodes, edges };
  }

  edgesFor(correlationId: string): LineageEdge[] {
    return this.edges.filter((e) => e.correlationId === correlationId);
  }

  snapshot(correlationId?: string): LineageGraphSnapshot {
    const edges = correlationId
      ? this.edgesFor(correlationId)
      : [...this.edges];
    const nodeIds = new Set<string>();
    for (const e of edges) {
      nodeIds.add(e.from);
      nodeIds.add(e.to);
    }
    const nodes =
      correlationId === undefined
        ? [...this.nodes.values()]
        : [...this.nodes.values()].filter((n) => nodeIds.has(n.id));
    return LineageGraphSnapshotSchema.parse({
      nodes,
      edges,
      capturedAt: new Date().toISOString(),
    });
  }

  clear(): void {
    this.nodes.clear();
    this.edges = [];
  }

  saveToFile(filePath: string): void {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, JSON.stringify(this.snapshot(), null, 2), "utf8");
  }

  loadFromFile(filePath: string): void {
    if (!existsSync(filePath)) return;
    const raw = JSON.parse(readFileSync(filePath, "utf8")) as unknown;
    const parsed = LineageGraphSnapshotSchema.parse(raw);
    this.nodes.clear();
    for (const node of parsed.nodes) {
      this.nodes.set(node.id, node);
    }
    this.edges = [...parsed.edges];
  }
}
