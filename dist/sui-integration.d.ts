/**
 * Sui Integration for Injection Hunter
 *
 * Simplified Sui blockchain integration for audit proofs
 * Compatible with @mysten/sui v1.x
 */
export interface SuiConfig {
    network: 'mainnet' | 'testnet' | 'devnet';
    packageId?: string;
    registryObjId?: string;
}
export interface ThreatStat {
    threatType: string;
    count: number;
    lastSeen: string;
}
export interface SuiProof {
    scanId: string;
    timestamp: string;
    riskLevel: string;
    threatHash: string;
    signature: string;
    network: string;
}
export declare class SuiIntegration {
    private config;
    constructor(config?: Partial<SuiConfig>);
    /**
     * Get current network
     */
    getNetwork(): string;
    /**
     * Create cryptographic proof of scan (off-chain compatible)
     */
    createScanProof(scanId: string, riskLevel: string, threatSummary: {
        type: string;
        count: number;
    }[]): SuiProof;
    /**
     * Verify a scan proof
     */
    verifyProof(proof: SuiProof): {
        valid: boolean;
        message: string;
    };
    /**
     * Record threat statistics (mock on-chain storage)
     */
    recordThreatStatsLocally(threatStats: ThreatStat[]): {
        txDigest: string;
        proof: SuiProof;
    };
    /**
     * Format threat stats for on-chain storage
     */
    formatForChain(threatStats: ThreatStat[]): {
        types: string[];
        counts: string[];
        timestamp: string;
    };
    /**
     * Generate statistics report
     */
    generateStatsReport(stats: ThreatStat[]): {
        total: number;
        byRisk: Record<string, number>;
        topThreats: {
            type: string;
            count: number;
        }[];
        reportHash: string;
    };
    /**
     * Helper: Hash string to hex
     */
    private hashString;
}
export declare function demoSuiIntegration(): Promise<void>;
