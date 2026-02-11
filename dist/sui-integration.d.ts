/**
 * Sui Integration for Injection Hunter
 *
 * Sui blockchain integration for decentralized audit proofs.
 *
 * This module provides the interface for:
 * - Wallet connection
 * - Transaction signing
 * - On-chain proof submission
 *
 * Note: Requires @mysten/sui v2.x SDK. In production, this would
 * be connected to real Sui smart contracts for audit proof storage.
 *
 * The integration demonstrates proper Sui blockchain interaction patterns
 * including gas estimation, transaction building, and signature handling.
 */
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
    txDigest?: string;
}
export interface SuiConfig {
    network: 'mainnet' | 'testnet' | 'devnet';
    packageId?: string;
    registryObjId?: string;
}
export interface WalletState {
    connected: boolean;
    address: string | null;
    network: string;
    balance: {
        sui: string;
        usd: string;
    } | null;
}
export declare class SuiIntegration {
    private config;
    private walletState;
    constructor(config?: Partial<SuiConfig>);
    /**
     * Get current network
     */
    getNetwork(): string;
    /**
     * Get wallet state
     */
    getWalletState(): WalletState;
    /**
     * Get wallet address (if connected)
     */
    getAddress(): string | null;
    /**
     * Check if wallet is connected
     */
    isConnected(): boolean;
    /**
     * Initialize with private key (hex format)
     *
     * In production, this would:
     * 1. Import Ed25519Keypair from @mysten/sui/keypairs/ed25519
     * 2. Create keypair from hex secret key
     * 3. Derive public key address
     * 4. Fetch initial balance
     *
     * Example:
     * const { Ed25519Keypair } = await import('@mysten/sui/keypairs/ed25519');
     * const keypair = Ed25519Keypair.fromSecretKey(Buffer.from(hexKey, 'hex'));
     * const address = keypair.getPublicKey().toSuiAddress();
     */
    initializeWithKeypair(privateKey: string): Promise<boolean>;
    /**
     * Derive Sui address from private key
     * This is a simplified version - production would use proper crypto
     */
    private deriveAddressFromKey;
    /**
     * Create cryptographic proof of scan
     *
     * This proof can be submitted to Sui blockchain as an immutable
     * record of the security scan. In production, this would:
     * 1. Serialize the scan result
     * 2. Create a hash commitment
     * 3. Optionally sign with wallet keypair
     */
    createScanProof(scanId: string, riskLevel: string, threatSummary: {
        type: string;
        count: number;
    }[]): SuiProof;
    /**
     * Submit proof to Sui blockchain
     *
     * In production, this would:
     * 1. Build a Transaction using @mysten/sui/transactions
     * 2. Call a Move contract to store the proof
     * 3. Sign with user's wallet
     * 4. Execute and wait for confirmation
     *
     * Example Move contract interface:
     * public entry fun record_scan(
     *   registry: &mut ThreatRegistry,
     *   scan_id: String,
     *   risk_level: String,
     *   threat_hash: String,
     *   ctx: &mut TxContext
     * )
     */
    submitProofToChain(proof: SuiProof): Promise<{
        success: boolean;
        txDigest?: string;
        error?: string;
    }>;
    /**
     * Record threat statistics on-chain
     *
     * In production, this aggregates threat data and submits to
     * a shared registry contract accessible by all Sui users.
     */
    recordThreatStatsOnChain(threatStats: ThreatStat[]): Promise<{
        success: boolean;
        txDigest?: string;
        proof?: SuiProof;
        error?: string;
    }>;
    /**
     * Get proof from blockchain
     *
     * In production, this would query the Move contract's table
     * to retrieve historical proofs by scan ID.
     */
    getProofFromChain(proofId: string): Promise<{
        found: boolean;
        proof?: SuiProof;
        timestamp?: string;
        onChain: boolean;
    }>;
    /**
     * Verify a scan proof
     *
     * Verifies that the hash in the proof matches the expected
     * hash for the given scan data.
     */
    verifyProof(proof: SuiProof): {
        valid: boolean;
        message: string;
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
     * Estimate gas for a transaction
     *
     * In production, this uses:
     * await client.getReferenceGasPrice();
     * and estimates based on transaction size
     */
    estimateGas(): Promise<{
        price: number;
        budget: number;
    } | null>;
    /**
     * Helper: Hash string to hex
     */
    private hashString;
}
export declare function demoSuiIntegration(): Promise<void>;
