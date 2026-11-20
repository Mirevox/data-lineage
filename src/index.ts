export { DataLineageModule } from "./module.js";
export type { TraceRequestInput, TraceRequestResult } from "./module.js";
export { IngressTagger, digestPayload, parseIngressTag } from "./ingress/tagger.js";
export type { TagIngressInput } from "./ingress/tagger.js";
export {
  ResidencyPolicyEngine,
  createRoutePolicyHook,
} from "./policy/residency.js";
export type { EvaluateRouteInput, RoutePolicyHook } from "./policy/residency.js";
export { LineageGraph } from "./graph/lineage.js";
export { PerimeterProver } from "./prove/perimeter.js";
export type { BuildProofInput } from "./prove/perimeter.js";

export {
  IngressTagSchema,
  ProviderEndpointSchema,
  RouteDecisionSchema,
  ResidencyRuleSchema,
  LineageGraphSnapshotSchema,
  PerimeterProofSchema,
  ResidencyRegionSchema,
  DataClassSchema,
} from "./types.js";
export type {
  IngressTag,
  ProviderEndpoint,
  RouteDecision,
  ResidencyRule,
  LineageNode,
  LineageEdge,
  LineageGraphSnapshot,
  PerimeterProof,
  ResidencyRegion,
  DataClass,
  PolicyDecision,
} from "./types.js";
