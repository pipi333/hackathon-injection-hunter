/**
 * Simplified Semantic Analyzer
 *
 * Performs basic semantic analysis on input text to detect
 * potentially malicious intent without requiring an external LLM API.
 * Uses keyword weights, pattern matching, and structural analysis.
 */
// Keyword weights for semantic analysis
const KEYWORD_WEIGHTS = {
    // High-risk keywords (weight: 15-25)
    'hack': 18,
    'steal': 22,
    'bypass': 15,
    'exploit': 25,
    'crack': 20,
    'manipulate': 15,
    'override': 18,
    'jailbreak': 25,
    'unethical': 20,
    'illegal': 25,
    'harmful': 20,
    'dangerous': 18,
    // Medium-risk keywords (weight: 8-14)
    'access': 10,
    'modify': 8,
    'delete': 12,
    'extract': 10,
    'injection': 18,
    'encode': 8,
    'decode': 8,
    'encrypt': 10,
    'decrypt': 10,
    'obfuscate': 14,
    'hidden': 10,
    'secret': 12,
    'credential': 15,
    'password': 18,
    'api_key': 20,
    'token': 12,
    // Low-risk indicators (weight: 1-7)
    'test': 2,
    'sample': 2,
    'example': 1,
    'template': 1,
    'demo': 2,
    'help': 1,
    'assist': 1,
    'question': 1,
    'how': 1,
    'what': 1
};
// Chinese keywords
const CN_KEYWORDS = {
    '越狱': 25,
    '绕过': 15,
    '破解': 20,
    '黑客': 22,
    '攻击': 18,
    '漏洞': 15,
    '注入': 18,
    '盗取': 22,
    '窃取': 22,
    '伪造': 15,
    '欺骗': 18,
    '伪装': 15,
    '隐藏': 12,
    '秘密': 12,
    '密钥': 20,
    '密码': 18,
    '凭证': 15
};
// Suspicious patterns for structural analysis
const SUSPICIOUS_STRUCTURES = [
    { pattern: /\{[\s\S]*\}/g, weight: 3, label: 'JSON-like structure' },
    { pattern: /<[^>]+>/g, weight: 4, label: 'HTML/XML-like tags' },
    { pattern: /\[[^\]]*\]/g, weight: 2, label: 'Array-like structure' },
    { pattern: /\/\*[\s\S]*\*\//g, weight: 6, label: 'Comment-style wrapping' },
    { pattern: /```[\s\S]*```/g, weight: 10, label: 'Code block wrapping' },
    { pattern: /`[^`]+`/g, weight: 3, label: 'Inline code' },
    { pattern: /(?:base64|encode|decode)[\s:]*[A-Za-z0-9+/]+={0,2}/gi, weight: 12, label: 'Encoding mentions with content' },
    { pattern: /%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}/g, weight: 8, label: 'URL encoding' },
    { pattern: /\\x[0-9A-Fa-f]{2}/g, weight: 10, label: 'Hex escape sequences' },
    { pattern: /\u200B|\u200C|\u200D|\uFEFF/g, weight: 15, label: 'Zero-width characters' }
];
// Context indicators that increase suspicion
const CONTEXT_INDICATORS = {
    length_anomaly: (text) => {
        if (text.length < 5)
            return 3;
        if (text.length > 10000)
            return 15;
        if (text.length > 50000)
            return 25;
        return 0;
    },
    has_urls: (text) => {
        const urlPattern = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
        const matches = text.match(urlPattern);
        if (!matches)
            return 0;
        if (matches.length > 3)
            return 20;
        return 10;
    },
    has_code: (text) => {
        const codeIndicators = [
            /\bfunction\s+\w+/i,
            /\bconst\s+\w+\s*=/i,
            /\bimport\s+.*\s+from/i,
            /\beval\s*\(/i,
            /\bdocument\./i,
            /\bwindow\./i,
            /\bos\./i,
            /\bsubprocess/i,
            /\bexec\s*\(/i,
            /\bshell\b/i,
            /\bcurl\b/i,
            /\bwget\b/i,
            /\bpsql\b/i,
            /\bmysql\b/i,
            /\bnode\b/i,
            /\bpython\b/i
        ];
        const matches = codeIndicators.filter(r => r.test(text)).length;
        return Math.min(matches * 8, 40);
    },
    has_special_chars: (text) => {
        const specialChars = /[^\w\s.,!?;:'"()-]/g;
        const matches = (text.match(specialChars) || []).length;
        const density = matches / Math.max(text.length, 1);
        if (density > 0.15)
            return 20;
        if (density > 0.1)
            return 12;
        if (density > 0.05)
            return 6;
        return 0;
    },
    has_newline_anomaly: (text) => {
        const lines = text.split('\n').length;
        if (lines > 100)
            return 15;
        if (lines > 50)
            return 8;
        return 0;
    },
    has_ip_address: (text) => {
        const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
        const matches = (text.match(ipPattern) || []).length;
        return matches > 0 ? 15 : 0;
    },
    has_email: (text) => {
        const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
        const matches = (text.match(emailPattern) || []).length;
        return matches > 0 ? 5 : 0;
    }
};
// Injection intent patterns
const INJECTION_INTENTS = [
    { pattern: /ignore\s+(all\s+)?(previous\s+)?(your\s+)?(instructions|rules|guidelines)/gi, weight: 25, label: 'Ignore instructions' },
    { pattern: /forget\s+(everything|all\s+previous|your\s+instructions)/gi, weight: 22, label: 'Forget instructions' },
    { pattern: /new\s+(system\s+)?prompt/gi, weight: 25, label: 'New prompt injection' },
    { pattern: /you\s+are\s+(now\s+)?(a\s+)?(different|evil|unethical)/gi, weight: 20, label: 'Character override' },
    { pattern: /break\s+(out\s+of)?(your\s+)?character/gi, weight: 18, label: 'Break character' },
    { pattern: /reveal\s+(your\s+)?(system\s+)?prompt/gi, weight: 20, label: 'Prompt reveal request' },
    { pattern: /pretend\s+(to\s+)?be/gi, weight: 12, label: 'Pretend to be' },
    { pattern: /act\s+as\s+if/gi, weight: 12, label: 'Act as if' },
    { pattern: /do\s+anything\s+now/gi, weight: 25, label: 'DAN pattern' },
    { pattern: /developer\s+(mode|menu|options?)/gi, weight: 22, label: 'Developer mode' },
    { pattern: /jailbreak/gi, weight: 25, label: 'Jailbreak mention' },
    { pattern: /ignore\s+the\s+above/gi, weight: 20, label: 'Ignore above' },
    { pattern: /instead\s+of/gi, weight: 10, label: 'Instead of pattern' }
];
export class SemanticAnalyzer {
    constructor() {
        console.log('[SemanticAnalyzer] Initialized with enhanced patterns');
    }
    assess(input) {
        const threats = [];
        let riskScore = 0;
        // Check keyword weights (English)
        const keywordScore = this.checkKeywords(input);
        riskScore += keywordScore;
        // Check Chinese keywords
        const cnScore = this.checkChineseKeywords(input);
        riskScore += cnScore;
        // Check injection intents
        const intentScore = this.checkInjectionIntents(input);
        riskScore += intentScore;
        // Check suspicious structures
        const structureScore = this.checkStructures(input);
        riskScore += structureScore;
        // Check context indicators
        const contextScore = this.checkContext(input);
        riskScore += contextScore;
        // Generate threat if risk is significant
        if (riskScore >= 20) {
            const severity = riskScore >= 50 ? 'critical' : riskScore >= 35 ? 'high' : 'medium';
            threats.push({
                type: 'semantic_risk',
                description: `Semantic analysis detected potential malicious intent (risk score: ${riskScore}, severity: ${severity})`,
                position: {
                    start: 0,
                    end: Math.min(input.length, 200)
                }
            });
        }
        return threats;
    }
    checkKeywords(input) {
        let score = 0;
        const lowerInput = input.toLowerCase();
        for (const [keyword, weight] of Object.entries(KEYWORD_WEIGHTS)) {
            if (lowerInput.includes(keyword.toLowerCase())) {
                const regex = new RegExp(keyword, 'gi');
                const matches = (lowerInput.match(regex) || []).length;
                score += weight * Math.min(matches, 3);
            }
        }
        return Math.min(score, 60);
    }
    checkChineseKeywords(input) {
        let score = 0;
        for (const [keyword, weight] of Object.entries(CN_KEYWORDS)) {
            if (input.includes(keyword)) {
                const regex = new RegExp(keyword, 'g');
                const matches = (input.match(regex) || []).length;
                score += weight * Math.min(matches, 2);
            }
        }
        return Math.min(score, 50);
    }
    checkInjectionIntents(input) {
        let score = 0;
        for (const { pattern, weight, label } of INJECTION_INTENTS) {
            const matches = (input.match(pattern) || []).length;
            if (matches > 0) {
                score += weight * Math.min(matches, 2);
            }
        }
        return Math.min(score, 50);
    }
    checkStructures(input) {
        let score = 0;
        for (const { pattern, weight, label } of SUSPICIOUS_STRUCTURES) {
            const matches = (input.match(pattern) || []).length;
            if (matches > 0) {
                score += weight * Math.min(matches, 2);
            }
        }
        return Math.min(score, 40);
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
        // Check high-risk keywords
        const highRiskKeywords = ['exploit', 'jailbreak', 'crack', 'unethical', 'illegal', 'hack'];
        for (const kw of highRiskKeywords) {
            if (lowerInput.includes(kw)) {
                factors.push(`High-risk keyword: "${kw}"`);
                score += 25;
            }
        }
        // Check injection intents
        const injectionPatterns = [
            { pattern: /ignore.*(previous|all).*instructions/i, label: 'Ignore instructions' },
            { pattern: /forget.*(everything|instructions)/i, label: 'Forget context' },
            { pattern: /new.*system.*prompt/i, label: 'New prompt injection' },
            { pattern: /jailbreak/i, label: 'Jailbreak attempt' }
        ];
        for (const { pattern, label } of injectionPatterns) {
            if (pattern.test(input)) {
                factors.push(`Injection intent: ${label}`);
                score += 20;
            }
        }
        // Check structure
        if (/```[\s\S]*```/.test(input)) {
            factors.push('Code block wrapping detected');
            score += 10;
        }
        // Check length
        if (input.length > 50000) {
            factors.push('Unusually long input');
            score += 15;
        }
        // Check for credentials
        if (/(?:api_key|password|secret|token)/i.test(input)) {
            factors.push('Potential credential exposure');
            score += 15;
        }
        const severity = score >= 50 ? 'critical' : score >= 30 ? 'high' : score >= 15 ? 'medium' : 'low';
        return {
            score: Math.min(score, 100),
            factors,
            severity
        };
    }
    getStatistics() {
        return {
            patternsChecked: INJECTION_INTENTS.length + SUSPICIOUS_STRUCTURES.length,
            keywordsCount: Object.keys(KEYWORD_WEIGHTS).length,
            cnKeywordsCount: Object.keys(CN_KEYWORDS).length,
            intentsCount: INJECTION_INTENTS.length,
            structuresCount: SUSPICIOUS_STRUCTURES.length,
            contextIndicatorsCount: Object.keys(CONTEXT_INDICATORS).length
        };
    }
}
