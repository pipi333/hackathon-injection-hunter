/**
 * Audit Logger - Records all scan results for security review
 */
export interface AuditLogEntry {
    id: string;
    timestamp: string;
    inputHash: string;
    risk: string;
    score: number;
    threatCount: number;
    threats: {
        type: string;
        description: string;
    }[];
    action: string;
}
export declare class AuditLogger {
    private logPath;
    private logs;
    constructor(logPath?: string);
    private ensureLogDir;
    private loadLogs;
    log(input: string, risk: string, score: number, threats: {
        type: string;
        description: string;
    }[], action?: string): void;
    getLogs(limit?: number): AuditLogEntry[];
    getLogsByRisk(risk: string): AuditLogEntry[];
    getStatistics(): {
        total: number;
        byRisk: Record<string, number>;
        recentThreats: {
            type: string;
            count: number;
        }[];
    };
    exportJson(): string;
    clear(): void;
    private saveLogs;
    private hashInput;
}
