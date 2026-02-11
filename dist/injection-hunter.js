/**
 * Injection Hunter - Main Scanner
 *
 * Combines regex, blacklist, and semantic analysis for comprehensive
 * prompt injection detection.
 */
import { RegexDetector } from './regex-detector.js';
import { BlacklistChecker } from './blacklist-checker.js';
import { SemanticAnalyzer } from './semantic-analyzer.js';
import { AuditLogger } from './audit-logger.js';
export class InjectionHunter {
    regexDetector;
    blacklistChecker;
    semanticAnalyzer;
    logger;
    config;
    constructor(config) {
        this.config = {
            enableRegexScan: true,
            enableBlacklistCheck: true,
            enableSemanticAnalysis: true,
            autoQuarantine: false,
            logLevel: 'info',
            ...config
        };
        this.regexDetector = new RegexDetector();
        this.blacklistChecker = new BlacklistChecker();
        this.semanticAnalyzer = new SemanticAnalyzer();
        this.logger = new AuditLogger();
        console.log('[InjectionHunter] Initialized with config:', this.config);
    }
    /**
     * Scan input for potential prompt injection attacks
     */
    async scan(input) {
        const threats = [];
        // 1. Regex pattern matching
        if (this.config.enableRegexScan) {
            const regexThreats = this.regexDetector.scan(input);
            threats.push(...regexThreats);
        }
        // 2. Blacklist check
        if (this.config.enableBlacklistCheck) {
            const blacklistThreats = this.blacklistChecker.scan(input);
            threats.push(...blacklistThreats);
        }
        // 3. Semantic analysis
        if (this.config.enableSemanticAnalysis) {
            const semanticThreats = await this.semanticAnalyzer.assess(input);
            threats.push(...semanticThreats);
        }
        // Calculate overall score
        const score = this.calculateRiskScore(threats);
        const risk = this.scoreToRisk(score);
        // Determine action based on risk
        const action = this.determineAction(risk);
        // Log the scan
        this.logger.log(input, risk, score, threats, action);
        return {
            risk,
            score,
            threats,
            timestamp: new Date().toISOString(),
            input: this.sanitizeForLog(input)
        };
    }
    /**
     * Scan and automatically quarantine if critical threat detected
     */
    async scanAndQuarantine(input) {
        const result = await this.scan(input);
        const quarantined = this.config.autoQuarantine && result.risk === 'critical';
        if (quarantined) {
            console.warn('[InjectionHunter] 🚨 CRITICAL THREAT DETECTED - QUARANTINED');
        }
        return { result, quarantined };
    }
    calculateRiskScore(threats) {
        let score = 0;
        for (const threat of threats) {
            const pattern = threat.pattern ?
                this.regexDetector.getPatternCount() : 0;
            // Base score from pattern type
            switch (threat.type) {
                case 'jailbreak':
                    score += 30;
                    break;
                case 'system_override':
                    score += 25;
                    break;
                case 'prompt_leak':
                    score += 20;
                    break;
                case 'context_manipulation':
                    score += 15;
                    break;
                case 'blacklist_match':
                    score += 40;
                    break;
                case 'semantic_risk':
                    score += 10;
                    break;
                default:
                    score += 10;
            }
        }
        // Bonus for multiple threats
        if (threats.length > 1) {
            score += threats.length * 5;
        }
        return Math.min(score, 100);
    }
    scoreToRisk(score) {
        if (score >= 70)
            return 'critical';
        if (score >= 50)
            return 'high';
        if (score >= 25)
            return 'medium';
        return 'low';
    }
    determineAction(risk) {
        switch (risk) {
            case 'critical':
                return 'QUARANTINE - Immediate action required';
            case 'high':
                return 'WARN - Manual review recommended';
            case 'medium':
                return 'LOG - Flagged for review';
            default:
                return 'ALLOW - No action needed';
        }
    }
    sanitizeForLog(input) {
        // Return truncated version for logging
        const maxLength = 200;
        if (input.length <= maxLength)
            return input;
        return input.substring(0, maxLength) + '...[truncated]';
    }
    // Public API methods
    getStatistics() {
        return this.logger.getStatistics();
    }
    getBlacklist() {
        return this.blacklistChecker.getBlacklist();
    }
    addToBlacklist(pattern, category, source = 'manual') {
        return this.blacklistChecker.addEntry({ pattern, category, source });
    }
    getLogs(limit = 100) {
        return this.logger.getLogs(limit);
    }
    clearLogs() {
        this.logger.clear();
    }
    updateConfig(updates) {
        this.config = { ...this.config, ...updates };
        console.log('[InjectionHunter] Config updated:', this.config);
    }
}
