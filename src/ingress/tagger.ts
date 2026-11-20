import { createHash, randomUUID } from "node:crypto";
import {
  DataClassSchema,
  IngressTagSchema,
  ResidencyRegionSchema,
  type DataClass,
  type IngressTag,
  type ResidencyRegion,
} from "../types.js";

export interface TagIngressInput {
  tenantId: string;
  sourceId: string;
  declaredResidency: ResidencyRegion;
  dataClasses?: DataClass[];
  labels?: Record<string, string>;
  /** Raw payload to bind a content digest (optional). */
  payload?: string | Uint8Array;
  correlationId?: string;
  now?: () => Date;
}

/**
 * Ingress tagging: stamp AI-bound requests before routing.
 * Tags are the unit of residency/policy evaluation and lineage correlation.
 */
export class IngressTagger {
  tag(input: TagIngressInput): IngressTag {
    const declaredResidency = ResidencyRegionSchema.parse(input.declaredResidency);
    const dataClasses = (input.dataClasses ?? []).map((c) =>
      DataClassSchema.parse(c),
    );
    const now = input.now?.() ?? new Date();
    const tag: IngressTag = {
      correlationId: input.correlationId ?? randomUUID(),
      tenantId: input.tenantId,
      sourceId: input.sourceId,
      declaredResidency,
      dataClasses,
      labels: input.labels ?? {},
      taggedAt: now.toISOString(),
    };
    if (input.payload !== undefined) {
      tag.contentDigest = digestPayload(input.payload);
    }
    return IngressTagSchema.parse(tag);
  }
}

export function digestPayload(payload: string | Uint8Array): string {
  const buf =
    typeof payload === "string" ? Buffer.from(payload, "utf8") : Buffer.from(payload);
  return `sha256:${createHash("sha256").update(buf).digest("hex")}`;
}

export function parseIngressTag(raw: unknown): IngressTag {
  return IngressTagSchema.parse(raw);
}
