/**
 * OpenClaw Skill Integration
 *
 * This skill enables OpenClaw agents to scan external inputs
 * for prompt injection attacks before processing.
 */
declare const INJECTION_HUNTER_SKILL: {
    name: string;
    description: string;
    parameters: {
        input: {
            type: string;
            description: string;
        };
        autoQuarantine: {
            type: string;
            description: string;
            default: boolean;
        };
    };
    scan(input: string, autoQuarantine?: boolean): Promise<{
        success: boolean;
        risk: import("./types.js").RiskLevel;
        score: number;
        threats: import("./types.js").Threat[];
        quarantined: boolean;
        message: string;
    }>;
    getActionMessage(risk: string, quarantined: boolean): string;
    getStatistics(): {
        total: number;
        byRisk: Record<string, number>;
        recentThreats: {
            type: string;
            count: number;
        }[];
    };
    addToBlacklist(pattern: string, category: string): string;
    getLogs(limit?: number): import("./audit-logger.js").AuditLogEntry[];
    configure(options: {
        enableRegex?: boolean;
        enableBlacklist?: boolean;
        enableSemantic?: boolean;
        autoQuarantine?: boolean;
    }): {
        success: boolean;
        message: string;
    };
    createOnChainProof(scanResult: {
        risk: string;
        score: number;
        threats: {
            type: string;
            count: number;
        }[];
    }): Promise<{
        success: boolean;
        proof: import("./sui-integration.js").SuiProof;
        message: string;
    }>;
    verifyOnChainProof(proofId: string): Promise<{
        found: boolean;
        proof?: import("./sui-integration.js").SuiProof;
        timestamp?: string;
        onChain: boolean;
    }>;
};
export default INJECTION_HUNTER_SKILL;
