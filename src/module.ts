import { LineageGraph } from "./graph/lineage.js";
import { IngressTagger, type TagIngressInput } from "./ingress/tagger.js";
import {
  createRoutePolicyHook,
  ResidencyPolicyEngine,
  type RoutePolicyHook,
} from "./policy/residency.js";
import { PerimeterProver } from "./prove/perimeter.js";
import type {
  IngressTag,
  LineageGraphSnapshot,
  PerimeterProof,
  ProviderEndpoint,
  ResidencyRule,
  RouteDecision,
} from "./types.js";

export interface TraceRequestInput extends TagIngressInput {
  candidate: ProviderEndpoint;
  alternatives?: ProviderEndpoint[];
  routerId?: string;
}

export interface TraceRequestResult {
  tag: IngressTag;
  decision: RouteDecision;
  graph: LineageGraphSnapshot;
  proof: PerimeterProof;
}

/**
 * Router-side data lineage module facade.
 * Wire `policyHook` into a smart-router before provider egress.
 */
export class DataLineageModule {
  readonly tagger = new IngressTagger();
  readonly policy: ResidencyPolicyEngine;
  readonly graph = new LineageGraph();
  readonly prover = new PerimeterProver();
  readonly policyHook: RoutePolicyHook;

  constructor(rules: ResidencyRule[] = []) {
    this.policy = new ResidencyPolicyEngine(rules);
    this.policyHook = createRoutePolicyHook(this.policy);
  }

  /** End-to-end: tag → evaluate → record lineage → issue software proof. */
  traceRequest(input: TraceRequestInput): TraceRequestResult {
    const tag = this.tagger.tag(input);
    const decision = this.policy.evaluate({
      tag,
      candidate: input.candidate,
      alternatives: input.alternatives,
      now: input.now,
    });
    const { nodes, edges } = this.graph.recordAiHop({
      tag,
      routerId: input.routerId,
      candidate: input.candidate,
      decision,
      now: input.now,
    });
    const proof = this.prover.build({
      tag,
      decision,
      edges,
      nodes,
      now: input.now,
    });
    return {
      tag,
      decision,
      graph: this.graph.snapshot(tag.correlationId),
      proof,
    };
  }

  getGraph(correlationId?: string): LineageGraphSnapshot {
    return this.graph.snapshot(correlationId);
  }
}
