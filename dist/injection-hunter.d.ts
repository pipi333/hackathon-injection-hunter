/**
 * Injection Hunter - Main Scanner
 *
 * Combines regex, blacklist, and semantic analysis for comprehensive
 * prompt injection detection.
 */
import type { ScanResult, SecurityConfig } from './types.js';
export declare class InjectionHunter {
    private regexDetector;
    private blacklistChecker;
    private semanticAnalyzer;
    private logger;
    private config;
    constructor(config?: Partial<SecurityConfig>);
    /**
     * Scan input for potential prompt injection attacks
     */
    scan(input: string): Promise<ScanResult>;
    /**
     * Scan and automatically quarantine if critical threat detected
     */
    scanAndQuarantine(input: string): Promise<{
        result: ScanResult;
        quarantined: boolean;
    }>;
    private calculateRiskScore;
    private scoreToRisk;
    private determineAction;
    private sanitizeForLog;
    getStatistics(): {
        total: number;
        byRisk: Record<string, number>;
        recentThreats: {
            type: string;
            count: number;
        }[];
    };
    getBlacklist(): import("./types.js").BlacklistEntry[];
    addToBlacklist(pattern: string, category: string, source?: string): string;
    getLogs(limit?: number): import("./audit-logger.js").AuditLogEntry[];
    clearLogs(): void;
    updateConfig(updates: Partial<SecurityConfig>): void;
}
