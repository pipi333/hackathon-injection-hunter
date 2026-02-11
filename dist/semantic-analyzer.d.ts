/**
 * Simplified Semantic Analyzer
 *
 * Performs basic semantic analysis on input text to detect
 * potentially malicious intent without requiring an external LLM API.
 */
import type { Threat } from './types.js';
export declare class SemanticAnalyzer {
    constructor();
    assess(input: string): Threat[];
    private checkKeywords;
    private checkStructures;
    private checkContext;
    getRiskExplanation(input: string): {
        score: number;
        factors: string[];
    };
}
