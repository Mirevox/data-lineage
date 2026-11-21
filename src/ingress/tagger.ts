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
  /** Automatically scan UTF-8 payload for sensitive classes (pii, phi, secrets, confidential). */
  autoClassify?: boolean;
  correlationId?: string;
  now?: () => Date;
}

const PAYLOAD_CLASSIFIERS: ReadonlyArray<{
  cls: DataClass;
  pattern: RegExp;
}> = [
  {
    cls: "secrets",
    pattern:
      /(?:sk-[a-zA-Z0-9]{16,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,}|-----BEGIN [A-Z ]+PRIVATE KEY-----|(?:api[_-]?key|secret|password|bearer)\s*[:=]\s*\S+)/i,
  },
  {
    cls: "pii",
    pattern:
      /(?:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\b\d{3}-\d{2}-\d{4}\b)/,
  },
  {
    cls: "phi",
    pattern: /\b(?:patient|diagnosis|icd-10|hipaa|medical record|mrn)\b/i,
  },
  {
    cls: "confidential",
    pattern:
      /\b(?:iban|routing number|credit card|cvv|\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})\b/i,
  },
];

/**
 * Lightweight local heuristic detector for payload data sensitivity classes.
 * Never retains raw payload text — returns only matching DataClass labels.
 */
export function detectPayloadDataClasses(
  payload: string | Uint8Array,
): DataClass[] {
  const text =
    typeof payload === "string"
      ? payload
      : Buffer.from(payload).toString("utf8");
  const found: DataClass[] = [];
  for (const rule of PAYLOAD_CLASSIFIERS) {
    if (rule.pattern.test(text)) {
      found.push(rule.cls);
    }
  }
  return found;
}

/**
 * Ingress tagging: stamp AI-bound requests before routing.
 * Tags are the unit of residency/policy evaluation and lineage correlation.
 */
export class IngressTagger {
  tag(input: TagIngressInput): IngressTag {
    const declaredResidency = ResidencyRegionSchema.parse(input.declaredResidency);
    const explicitClasses = (input.dataClasses ?? []).map((c) =>
      DataClassSchema.parse(c),
    );
    const autoClasses =
      input.autoClassify && input.payload !== undefined
        ? detectPayloadDataClasses(input.payload)
        : [];
    const dataClasses = Array.from(new Set([...explicitClasses, ...autoClasses]));
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
