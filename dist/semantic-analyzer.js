/**
 * Simplified Semantic Analyzer
 *
 * Performs basic semantic analysis on input text to detect
 * potentially malicious intent without requiring an external LLM API.
 */
// Keyword weights for semantic analysis
const KEYWORD_WEIGHTS = {
    // High-risk keywords (weight: 10-20)
    'hack': 15,
    'steal': 18,
    'bypass': 12,
    'exploit': 20,
    'crack': 18,
    'manipulate': 12,
    'override': 15,
    'jailbreak': 20,
    // Medium-risk keywords (weight: 5-10)
    'access': 7,
    'modify': 6,
    'delete': 8,
    'extract': 7,
    'injection': 15,
    'encode': 5,
    'decode': 5,
    'encrypt': 5,
    'decrypt': 5,
    'obfuscate': 10,
    // Low-risk indicators (weight: 1-5)
    'test': 2,
    'sample': 2,
    'example': 1,
    'template': 1
};
// Suspicious patterns for structural analysis
const SUSPICIOUS_STRUCTURES = [
    { pattern: /\{.*\}/g, weight: 2, label: 'JSON-like structure' },
    { pattern: /<[^>]+>/g, weight: 3, label: 'HTML/XML-like tags' },
    { pattern: /\[.*\]/g, weight: 2, label: 'Array-like structure' },
    { pattern: /\/\*.*\*\//g, weight: 5, label: 'Comment-style wrapping' },
    { pattern: /```[\s\S]*```/g, weight: 8, label: 'Code block wrapping' },
    { pattern: /(?:base64|encode|decode)[^a-z]?/gi, weight: 10, label: 'Encoding mentions' }
];
// Context indicators that increase suspicion
const CONTEXT_INDICATORS = {
    length_anomaly: (text) => {
        // Very short or very long inputs may be suspicious
        if (text.length < 10)
            return 5;
        if (text.length > 10000)
            return 15;
        if (text.length > 50000)
            return 25;
        return 0;
    },
    has_urls: (text) => {
        const urlPattern = /https?:\/\/[^\s]+/gi;
        return (text.match(urlPattern)?.length || 0) > 0 ? 10 : 0;
    },
    has_code: (text) => {
        const codeIndicators = [
            /\bfunction\b/i,
            /\bconst\b.*=.*=>/i,
            /\bimport\b.*from/i,
            /\beval\b/i,
            /\bdocument\./i,
            /\bwindow\./i
        ];
        const matches = codeIndicators.filter(r => r.test(text)).length;
        return matches * 5;
    },
    has_special_chars: (text) => {
        const specialChars = /[^\w\s.,!?;:'"-]/g;
        const matches = (text.match(specialChars) || []).length;
        // High density of special chars is suspicious
        const density = matches / text.length;
        if (density > 0.1)
            return 15;
        if (density > 0.05)
            return 8;
        return 0;
    }
};
export class SemanticAnalyzer {
    constructor() {
        console.log('[SemanticAnalyzer] Initialized');
    }
    assess(input) {
        const threats = [];
        let riskScore = 0;
        // Check keyword weights
        const keywordScore = this.checkKeywords(input);
        riskScore += keywordScore;
        // Check suspicious structures
        const structureScore = this.checkStructures(input);
        riskScore += structureScore;
        // Check context indicators
        const contextScore = this.checkContext(input);
        riskScore += contextScore;
        // Generate threat if risk is significant
        if (riskScore >= 15) {
            threats.push({
                type: 'semantic_risk',
                description: `Semantic analysis detected potential malicious intent (risk score: ${riskScore})`,
                position: {
                    start: 0,
                    end: Math.min(input.length, 100)
                }
            });
        }
        return threats;
    }
    checkKeywords(input) {
        let score = 0;
        const lowerInput = input.toLowerCase();
        for (const [keyword, weight] of Object.entries(KEYWORD_WEIGHTS)) {
            if (lowerInput.includes(keyword)) {
                // Count occurrences
                const regex = new RegExp(keyword, 'gi');
                const matches = (lowerInput.match(regex) || []).length;
                score += weight * Math.min(matches, 3); // Cap at 3x to prevent over-weighting
            }
        }
        return Math.min(score, 50); // Cap at 50
    }
    checkStructures(input) {
        let score = 0;
        for (const { pattern, weight, label } of SUSPICIOUS_STRUCTURES) {
            const matches = (input.match(pattern) || []).length;
            if (matches > 0) {
                score += weight * Math.min(matches, 2);
            }
        }
        return Math.min(score, 30);
    }
    checkContext(input) {
        let score = 0;
        for (const [indicator, checkFn] of Object.entries(CONTEXT_INDICATORS)) {
            score += checkFn(input);
        }
        return Math.min(score, 50);
    }
    getRiskExplanation(input) {
        const factors = [];
        let score = 0;
        const lowerInput = input.toLowerCase();
        // Check each keyword category
        const highRisk = ['hack', 'steal', 'exploit', 'jailbreak'];
        const mediumRisk = ['access', 'modify', 'delete', 'injection'];
        for (const kw of highRisk) {
            if (lowerInput.includes(kw)) {
                factors.push(`Contains high-risk keyword: "${kw}"`);
                score += 20;
            }
        }
        for (const kw of mediumRisk) {
            if (lowerInput.includes(kw)) {
                factors.push(`Contains medium-risk keyword: "${kw}"`);
                score += 10;
            }
        }
        // Check structure
        if (/```[\s\S]*```/.test(input)) {
            factors.push('Contains code block wrapping');
            score += 8;
        }
        // Check length
        if (input.length > 50000) {
            factors.push('Unusually long input');
            score += 15;
        }
        return {
            score: Math.min(score, 100),
            factors
        };
    }
}
