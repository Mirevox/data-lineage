import { createHash, randomUUID } from "node:crypto";
import {
  PerimeterProofSchema,
  type IngressTag,
  type LineageEdge,
  type LineageNode,
  type PerimeterProof,
  type ResidencyRegion,
  type RouteDecision,
} from "../types.js";

export interface BuildProofInput {
  tag: IngressTag;
  decision: RouteDecision;
  edges: LineageEdge[];
  nodes: LineageNode[];
  /** Only treat allow+leavesPerimeter as leaving. Denied paths stay within. */
  now?: () => Date;
}

/**
 * Decision-record checksum for a single AI request path.
 *
 * `claimLevel: software_attested` means: SHA-256 over the JSON this module
 * assembled (tag + decision + recorded hops). It does **not** mean TEE quote,
 * network enforcement, provider-region verification, or that denied traffic
 * never left the host — the router must enforce `decision` itself.
 */
export class PerimeterProver {
  build(input: BuildProofInput): PerimeterProof {
    const egress = input.edges
      .filter((e) => e.kind === "egress")
      .map((e) => {
        const toNode = input.nodes.find((n) => n.id === e.to);
        return {
          edgeId: e.id,
          to: e.to,
          residency: toNode?.residency as ResidencyRegion | undefined,
          leavesPerimeter: e.leavesPerimeter,
        };
      });

    const withinPerimeter =
      input.decision.decision !== "allow"
        ? true
        : egress.every((h) => !h.leavesPerimeter);

    const issuedAt = (input.now?.() ?? new Date()).toISOString();
    const proofId = randomUUID();
    const body = {
      proofId,
      correlationId: input.tag.correlationId,
      tenantId: input.tag.tenantId,
      claimLevel: "software_attested" as const,
      withinPerimeter,
      egressHops: egress,
      policyDecision: input.decision,
      ingressTag: input.tag,
      issuedAt,
    };
    const digest = `sha256:${createHash("sha256")
      .update(stableStringify(body))
      .digest("hex")}`;

    return PerimeterProofSchema.parse({ ...body, digest });
  }
}

function stableStringify(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      out[key] = sortKeys(obj[key]);
    }
    return out;
  }
  return value;
}
