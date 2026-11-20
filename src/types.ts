import { z } from "zod";

/** ISO-ish residency / region tags used for policy. */
export const ResidencyRegionSchema = z.enum([
  "eu",
  "us",
  "uk",
  "ca",
  "apac",
  "global",
  "onprem",
  "unknown",
]);
export type ResidencyRegion = z.infer<typeof ResidencyRegionSchema>;

export const DataClassSchema = z.enum([
  "public",
  "internal",
  "confidential",
  "restricted",
  "pii",
  "phi",
  "secrets",
]);
export type DataClass = z.infer<typeof DataClassSchema>;

export const IngressTagSchema = z.object({
  correlationId: z.string().min(1),
  tenantId: z.string().min(1),
  sourceId: z.string().min(1),
  declaredResidency: ResidencyRegionSchema,
  dataClasses: z.array(DataClassSchema).default([]),
  labels: z.record(z.string(), z.string()).default({}),
  taggedAt: z.string().datetime(),
  /** Content hash of payload bytes (optional; for proof binding). */
  contentDigest: z.string().optional(),
});
export type IngressTag = z.infer<typeof IngressTagSchema>;

export const ProviderEndpointSchema = z.object({
  providerId: z.string().min(1),
  modelId: z.string().min(1),
  /** Declared residency of the provider endpoint / region. */
  residency: ResidencyRegionSchema,
  endpoint: z.string().url().or(z.string().startsWith("local://")),
  /** Caller-declared: whether this endpoint leaves the operator network (untrusted). */
  leavesPerimeter: z.boolean(),
});
export type ProviderEndpoint = z.infer<typeof ProviderEndpointSchema>;

export const PolicyDecisionSchema = z.enum([
  "allow",
  "deny",
  "reroute",
  "require_local",
]);
export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>;

export const RouteDecisionSchema = z.object({
  decision: PolicyDecisionSchema,
  reason: z.string(),
  matchedRuleId: z.string().optional(),
  suggestedEndpoint: ProviderEndpointSchema.optional(),
  /** Regions that would violate if used. */
  blockedResidencies: z.array(ResidencyRegionSchema).default([]),
  evaluatedAt: z.string().datetime(),
});
export type RouteDecision = z.infer<typeof RouteDecisionSchema>;

export const LineageNodeKindSchema = z.enum([
  "client",
  "ingress",
  "router",
  "policy",
  "provider",
  "region",
  "tool",
]);
export type LineageNodeKind = z.infer<typeof LineageNodeKindSchema>;

export const LineageNodeSchema = z.object({
  id: z.string().min(1),
  kind: LineageNodeKindSchema,
  label: z.string(),
  residency: ResidencyRegionSchema.optional(),
  meta: z.record(z.string(), z.unknown()).default({}),
});
export type LineageNode = z.infer<typeof LineageNodeSchema>;

export const LineageEdgeSchema = z.object({
  id: z.string().min(1),
  from: z.string().min(1),
  to: z.string().min(1),
  kind: z.enum(["ingress", "route", "egress", "tool_call", "policy_eval"]),
  correlationId: z.string(),
  leavesPerimeter: z.boolean().default(false),
  at: z.string().datetime(),
  meta: z.record(z.string(), z.unknown()).default({}),
});
export type LineageEdge = z.infer<typeof LineageEdgeSchema>;

export const LineageGraphSnapshotSchema = z.object({
  nodes: z.array(LineageNodeSchema),
  edges: z.array(LineageEdgeSchema),
  capturedAt: z.string().datetime(),
});
export type LineageGraphSnapshot = z.infer<typeof LineageGraphSnapshotSchema>;

export const PerimeterProofSchema = z.object({
  proofId: z.string().min(1),
  correlationId: z.string().min(1),
  tenantId: z.string().min(1),
  /** SHA-256 of assembled decision JSON only — not TEE or network enforcement. */
  claimLevel: z.literal("software_attested"),
  withinPerimeter: z.boolean(),
  egressHops: z.array(
    z.object({
      edgeId: z.string(),
      to: z.string(),
      residency: ResidencyRegionSchema.optional(),
      leavesPerimeter: z.boolean(),
    }),
  ),
  policyDecision: RouteDecisionSchema,
  ingressTag: IngressTagSchema,
  digest: z.string(),
  issuedAt: z.string().datetime(),
});
export type PerimeterProof = z.infer<typeof PerimeterProofSchema>;

export const ResidencyRuleSchema = z.object({
  id: z.string().min(1),
  description: z.string(),
  /** Tenant ids this rule applies to; empty = all. */
  tenants: z.array(z.string()).default([]),
  /** Allowed destination residencies. */
  allowResidencies: z.array(ResidencyRegionSchema).min(1),
  /** Data classes that trigger this rule when present on the tag. */
  whenDataClasses: z.array(DataClassSchema).default([]),
  /** Prefer on-prem / local when true. */
  preferLocal: z.boolean().default(false),
  /** Deny if any hop leaves perimeter. */
  denyLeavePerimeter: z.boolean().default(false),
  priority: z.number().int().default(100),
});
export type ResidencyRule = z.infer<typeof ResidencyRuleSchema>;
