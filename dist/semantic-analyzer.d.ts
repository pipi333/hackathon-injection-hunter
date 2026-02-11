/**
 * Simplified Semantic Analyzer
 *
 * Performs basic semantic analysis on input text to detect
 * potentially malicious intent without requiring an external LLM API.
 * Uses keyword weights, pattern matching, and structural analysis.
 */
import type { Threat } from './types.js';
export declare class SemanticAnalyzer {
    constructor();
    assess(input: string): Threat[];
    private checkKeywords;
    private checkChineseKeywords;
    private checkInjectionIntents;
    private checkStructures;
    private checkContext;
    getRiskExplanation(input: string): {
        score: number;
        factors: string[];
        severity: string;
    };
    getStatistics(): {
        patternsChecked: number;
        keywordsCount: number;
        cnKeywordsCount: number;
        intentsCount: number;
        structuresCount: number;
        contextIndicatorsCount: number;
    };
}
