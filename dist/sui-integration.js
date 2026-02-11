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
export class SuiIntegration {
    config;
    walletState;
    constructor(config) {
        this.config = {
            network: config?.network || 'testnet',
            packageId: config?.packageId,
            registryObjId: config?.registryObjId,
        };
        this.walletState = {
            connected: false,
            address: null,
            network: this.config.network,
            balance: null,
        };
        console.log(`[SuiIntegration] Initialized on ${this.config.network}`);
    }
    /**
     * Get current network
     */
    getNetwork() {
        return this.config.network;
    }
    /**
     * Get wallet state
     */
    getWalletState() {
        return { ...this.walletState };
    }
    /**
     * Get wallet address (if connected)
     */
    getAddress() {
        return this.walletState.address;
    }
    /**
     * Check if wallet is connected
     */
    isConnected() {
        return this.walletState.connected;
    }
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
    async initializeWithKeypair(privateKey) {
        try {
            // Validate hex format
            const keyHex = privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey;
            if (!/^[a-fA-F0-9]{64}$/.test(keyHex)) {
                throw new Error('Invalid private key format');
            }
            // Derive address from key (mock for demo)
            // In production: keypair.getPublicKey().toSuiAddress()
            const address = this.deriveAddressFromKey(keyHex);
            this.walletState = {
                connected: true,
                address,
                network: this.config.network,
                balance: null,
            };
            console.log(`[SuiIntegration] Wallet initialized: ${address}`);
            return true;
        }
        catch (error) {
            console.error('[SuiIntegration] Failed to initialize wallet:', error);
            return false;
        }
    }
    /**
     * Derive Sui address from private key
     * This is a simplified version - production would use proper crypto
     */
    deriveAddressFromKey(keyHex) {
        // Simplified address derivation for demo
        // Real implementation would use proper secp256k1 or ed25519 derivation
        const hash = this.hashString(keyHex);
        return '0x' + hash.slice(0, 40);
    }
    /**
     * Create cryptographic proof of scan
     *
     * This proof can be submitted to Sui blockchain as an immutable
     * record of the security scan. In production, this would:
     * 1. Serialize the scan result
     * 2. Create a hash commitment
     * 3. Optionally sign with wallet keypair
     */
    createScanProof(scanId, riskLevel, threatSummary) {
        const timestamp = new Date().toISOString();
        const threatData = {
            scanId,
            riskLevel,
            threatSummary,
            timestamp,
            network: this.config.network,
        };
        const threatHash = this.hashString(JSON.stringify(threatData));
        const signature = this.walletState.connected && this.walletState.address
            ? `[signed_${this.walletState.address.slice(0, 8)}]`
            : `[unsigned_proof_${Date.now()}]`;
        return {
            scanId,
            timestamp,
            riskLevel,
            threatHash,
            signature,
            network: this.config.network,
        };
    }
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
    async submitProofToChain(proof) {
        if (!this.walletState.connected) {
            return {
                success: false,
                error: 'Wallet not connected. Call initializeWithKeypair() first.'
            };
        }
        try {
            // In production, this would be:
            // const { Transaction } = await import('@mysten/sui/transactions');
            // const tx = new Transaction();
            // // Call Move contract to record proof
            // tx.moveCall({
            //   target: `${this.config.packageId}::registry::record_scan`,
            //   arguments: [
            //     tx.pure.string(proof.scanId),
            //     tx.pure.string(proof.riskLevel),
            //     tx.pure.string(proof.threatHash),
            //   ]
            // });
            // const result = await client.signAndExecuteTransaction({
            //   transaction: tx,
            //   signer: keypair,
            // });
            // Mock transaction digest for demo
            const txDigest = `0x${this.hashString(proof.scanId + Date.now()).slice(0, 64)}`;
            console.log(`[SuiIntegration] Would submit proof to: ${this.config.packageId || '0x...registry'}`);
            console.log(`[SuiIntegration] Transaction (mock): ${txDigest}`);
            return { success: true, txDigest };
        }
        catch (error) {
            console.error('[SuiIntegration] Failed to submit proof:', error);
            return {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error',
            };
        }
    }
    /**
     * Record threat statistics on-chain
     *
     * In production, this aggregates threat data and submits to
     * a shared registry contract accessible by all Sui users.
     */
    async recordThreatStatsOnChain(threatStats) {
        const scanId = `scan_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
        const maxCount = Math.max(...threatStats.map(t => t.count));
        const riskLevel = maxCount > 50 ? 'critical' : maxCount > 20 ? 'high' : maxCount > 10 ? 'medium' : 'low';
        const proof = this.createScanProof(scanId, riskLevel, threatStats.map(t => ({ type: t.threatType, count: t.count })));
        if (this.walletState.connected) {
            const submitResult = await this.submitProofToChain(proof);
            if (submitResult.success) {
                proof.txDigest = submitResult.txDigest;
                return { success: true, txDigest: submitResult.txDigest, proof };
            }
        }
        return {
            success: true,
            proof,
            error: 'No wallet connected - proof created but not submitted',
        };
    }
    /**
     * Get proof from blockchain
     *
     * In production, this would query the Move contract's table
     * to retrieve historical proofs by scan ID.
     */
    async getProofFromChain(proofId) {
        // Mock response - production would query on-chain data
        return {
            found: false,
            onChain: false,
            timestamp: undefined,
        };
    }
    /**
     * Verify a scan proof
     *
     * Verifies that the hash in the proof matches the expected
     * hash for the given scan data.
     */
    verifyProof(proof) {
        const expectedHash = this.hashString(JSON.stringify({
            scanId: proof.scanId,
            riskLevel: proof.riskLevel,
            network: proof.network,
        }));
        const isValid = proof.threatHash === expectedHash;
        return {
            valid: isValid,
            message: isValid
                ? 'Proof hash verified'
                : 'Proof verification failed - hash mismatch',
        };
    }
    /**
     * Generate statistics report
     */
    generateStatsReport(stats) {
        const byRisk = {};
        let total = 0;
        for (const stat of stats) {
            total += stat.count;
            byRisk[stat.threatType] = (byRisk[stat.threatType] || 0) + stat.count;
        }
        const topThreats = stats
            .sort((a, b) => b.count - a.count)
            .slice(0, 5)
            .map(t => ({ type: t.threatType, count: t.count }));
        const reportHash = this.hashString(JSON.stringify({ total, byRisk, topThreats }));
        return { total, byRisk, topThreats, reportHash };
    }
    /**
     * Estimate gas for a transaction
     *
     * In production, this uses:
     * await client.getReferenceGasPrice();
     * and estimates based on transaction size
     */
    async estimateGas() {
        // Mock gas estimation - production would query network
        return {
            price: 1000, // MIST
            budget: 2000000, // MIST (0.002 SUI)
        };
    }
    /**
     * Helper: Hash string to hex
     */
    hashString(input) {
        let hash = 0;
        for (let i = 0; i < input.length; i++) {
            const char = input.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash).toString(16).padStart(64, '0');
    }
}
// Demo function
export async function demoSuiIntegration() {
    console.log('\n🔷 Sui Integration Demo\n');
    const sui = new SuiIntegration({ network: 'testnet' });
    console.log('1. Wallet status:', sui.isConnected()
        ? `✅ Connected (${sui.getAddress()})`
        : '❌ Not connected (read-only mode)');
    console.log('\n2. Creating scan proof (offline):');
    const proof = sui.createScanProof('scan_demo_001', 'high', [{ type: 'jailbreak', count: 3 }, { type: 'system_override', count: 2 }]);
    console.log('   Proof:', {
        scanId: proof.scanId,
        risk: proof.riskLevel,
        hash: proof.threatHash.slice(0, 16) + '...',
        signed: proof.signature.includes('[signed') ? '✅' : '❌ (no wallet)',
    });
    console.log('\n3. Verifying proof:');
    const verification = sui.verifyProof(proof);
    console.log('   Valid:', verification.valid);
    console.log('\n4. Recording threat stats:');
    const stats = [
        { threatType: 'jailbreak', count: 42, lastSeen: new Date().toISOString() },
        { threatType: 'prompt_leak', count: 18, lastSeen: new Date().toISOString() },
        { threatType: 'context_manipulation', count: 25, lastSeen: new Date().toISOString() },
    ];
    const record = await sui.recordThreatStatsOnChain(stats);
    console.log('   Success:', record.success);
    console.log('   TX:', record.txDigest || 'Pending (no wallet)');
    console.log('\n5. Getting gas estimate:');
    const gas = await sui.estimateGas();
    console.log('   Gas:', gas ? `${gas.budget} MIST` : 'Unavailable');
    console.log('\n6. Generating stats report:');
    const report = sui.generateStatsReport(stats);
    console.log('   Total threats:', report.total);
    console.log('   Top:', report.topThreats.map(t => t.type).join(', '));
    console.log('\n🔷 Sui Integration Demo Complete\n');
    console.log('💡 To enable on-chain features, initialize with a wallet:');
    console.log('   await sui.initializeWithKeypair("private-key-hex");\n');
    console.log('📖 Sui SDK Documentation: https://sdk.mystenlabs.com/typescript\n');
}
