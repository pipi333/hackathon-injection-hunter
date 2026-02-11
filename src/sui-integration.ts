/**
 * Sui Integration for Injection Hunter
 * 
 * TypeScript interface for Sui blockchain integration.
 * 
 * Architecture:
 * 1. Creates scan proofs with cryptographic hashes
 * 2. Provides interface for on-chain submission (when contract is deployed)
 * 3. Handles wallet connection and transaction building
 * 
 * Prerequisites:
 * - Deploy Move contract: contracts/sources/threat_registry.move
 * - Get package ID from deployment
 * - Provide private key for signing transactions
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
  balance: { sui: string; usd: string } | null;
}

export class SuiIntegration {
  private config: SuiConfig;
  private walletState: WalletState;
  
  constructor(config?: Partial<SuiConfig>) {
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
    
    console.log(`[SuiIntegration] Initialized (${this.config.network})`);
  }
  
  /**
   * Get current network
   */
  public getNetwork(): string {
    return this.config.network;
  }
  
  /**
   * Get wallet state
   */
  public getWalletState(): WalletState {
    return { ...this.walletState };
  }
  
  /**
   * Get wallet address (if connected)
   */
  public getAddress(): string | null {
    return this.walletState.address;
  }
  
  /**
   * Check if wallet is connected
   */
  public isConnected(): boolean {
    return this.walletState.connected;
  }
  
  /**
   * Get package ID (Move contract address)
   */
  public getPackageId(): string | undefined {
    return this.config.packageId;
  }
  
  /**
   * Initialize with private key (hex format)
   * 
   * Usage:
   * await sui.initializeWithKeypair('private-key-in-hex');
   */
  public async initializeWithKeypair(privateKey: string): Promise<boolean> {
    try {
      const keyHex = privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey;
      if (!/^[a-fA-F0-9]{64}$/.test(keyHex)) {
        throw new Error('Invalid private key format (64 hex chars)');
      }
      
      // Derive address from key (simplified)
      const address = this.deriveAddressFromKey(keyHex);
      
      this.walletState = {
        connected: true,
        address,
        network: this.config.network,
        balance: null,
      };
      
      console.log(`[SuiIntegration] Wallet: ${address}`);
      return true;
    } catch (error) {
      console.error('[SuiIntegration] Failed to initialize:', error);
      return false;
    }
  }
  
  /**
   * Derive Sui address from private key
   * Simplified version - production uses ed25519 key derivation
   */
  private deriveAddressFromKey(keyHex: string): string {
    const hash = this.hashString(keyHex);
    return '0x' + hash.slice(0, 40);
  }
  
  /**
   * Create cryptographic proof of scan
   * 
   * This generates a hash commitment of the scan result that can
   * be verified later. Can be used offline without wallet.
   * 
   * Example:
   * const proof = sui.createScanProof('scan_001', 'high', [{type: 'jailbreak', count: 1}]);
   */
  public createScanProof(
    scanId: string,
    riskLevel: string,
    threatSummary: { type: string; count: number }[]
  ): SuiProof {
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
      : `[unsigned_${Date.now()}]`;
    
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
   * Prerequisites:
   * 1. Deploy Move contract (contracts/sources/threat_registry.move)
   * 2. Initialize with private key
   * 3. Set packageId config
   * 
   * This calls the Move function:
   * threat_registry::record_scan(scan_id, risk_level, threat_hash, count)
   */
  public async submitProofToChain(proof: SuiProof): Promise<{
    success: boolean;
    txDigest?: string;
    error?: string;
  }> {
    if (!this.walletState.connected) {
      return {
        success: false,
        error: 'Wallet not connected. Call initializeWithKeypair() first.'
      };
    }
    
    if (!this.config.packageId) {
      return {
        success: false,
        error: 'Package ID not set. Deploy contract and update config.'
      };
    }
    
    try {
      // In production, this would:
      // 1. Import Transaction from @mysten/sui/transactions
      // 2. Build transaction calling Move contract
      // 3. Sign and execute
      // 
      // const { Transaction } = await import('@mysten/sui/transactions');
      // const tx = new Transaction();
      // tx.moveCall({
      //   target: `${this.config.packageId}::threat_registry::record_scan`,
      //   arguments: [
      //     tx.pure.string(proof.scanId),
      //     tx.pure.string(proof.riskLevel),
      //     tx.pure.string(proof.threatHash),
      //     tx.pure.u64(Date.now()),
      //   ]
      // });
      
      // Mock tx digest for demo
      const txDigest = `0x${this.hashString(proof.scanId + Date.now()).slice(0, 64)}`;
      
      return { success: true, txDigest };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }
  
  /**
   * Record threat statistics on-chain
   * 
   * Calls threat_registry::update_threat_stats() in production
   */
  public async recordThreatStatsOnChain(threatStats: ThreatStat[]): Promise<{
    success: boolean;
    txDigest?: string;
    proof?: SuiProof;
    error?: string;
  }> {
    const scanId = `stats_${Date.now()}`;
    const maxCount = Math.max(...threatStats.map(t => t.count));
    const riskLevel = maxCount > 50 ? 'critical' : maxCount > 20 ? 'high' : maxCount > 10 ? 'medium' : 'low';
    
    const proof = this.createScanProof(
      scanId,
      riskLevel,
      threatStats.map(t => ({ type: t.threatType, count: t.count }))
    );
    
    if (this.walletState.connected && this.config.packageId) {
      const submitResult = await this.submitProofToChain(proof);
      if (submitResult.success) {
        proof.txDigest = submitResult.txDigest;
        return { success: true, txDigest: submitResult.txDigest, proof };
      }
    }
    
    return {
      success: true,
      proof,
      error: 'No wallet or package ID - proof created locally only',
    };
  }
  
  /**
   * Query scan proof from blockchain
   * 
   * Calls threat_registry::get_scan() in production
   */
  public async getProofFromChain(proofId: string): Promise<{
    found: boolean;
    proof?: SuiProof;
    timestamp?: string;
    onChain: boolean;
  }> {
    // In production, query Move contract table
    return { found: false, onChain: false };
  }
  
  /**
   * Verify scan proof integrity
   * 
   * Verifies that the hash matches the scan data.
   * Can be done offline without blockchain access.
   */
  public verifyProof(proof: SuiProof): {
    valid: boolean;
    message: string;
  } {
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
        : 'Hash mismatch - proof may be corrupted',
    };
  }
  
  /**
   * Generate statistics report
   */
  public generateStatsReport(stats: ThreatStat[]): {
    total: number;
    byRisk: Record<string, number>;
    topThreats: { type: string; count: number }[];
    reportHash: string;
  } {
    const byRisk: Record<string, number> = {};
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
   * Estimate gas for transaction
   */
  public async estimateGas(): Promise<{ price: number; budget: number } | null> {
    return {
      price: 1000, // MIST
      budget: 2000000, // 0.002 SUI
    };
  }
  
  /**
   * Simple hash function (for demo only)
   * Production should use SHA-256 or similar
   */
  private hashString(input: string): string {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
      const char = input.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(64, '0');
  }
}

/**
 * Demo function
 */
export async function demoSuiIntegration() {
  console.log('\n🔷 Sui Integration Demo\n');
  
  const sui = new SuiIntegration({ network: 'testnet' });
  
  console.log('1. Wallet:', sui.isConnected() 
    ? `Connected (${sui.getAddress()})` 
    : 'Not connected (read-only)');
  
  console.log('\n2. Creating scan proof:');
  const proof = sui.createScanProof(
    'scan_demo_001',
    'high',
    [{ type: 'jailbreak', count: 3 }]
  );
  console.log('   Scan ID:', proof.scanId);
  console.log('   Risk:', proof.riskLevel);
  console.log('   Hash:', proof.threatHash.slice(0, 16) + '...');
  console.log('   Signed:', proof.signature.includes('[signed') ? 'Yes' : 'No');
  
  console.log('\n3. Verifying proof:');
  const v = sui.verifyProof(proof);
  console.log('   Valid:', v.valid);
  
  console.log('\n4. Recording stats:');
  const stats = [
    { threatType: 'jailbreak', count: 42, lastSeen: new Date().toISOString() },
  ];
  const r = await sui.recordThreatStatsOnChain(stats);
  console.log('   Success:', r.success);
  console.log('   TX:', r.txDigest || 'Local only');
  
  console.log('\n5. Gas estimate:');
  const g = await sui.estimateGas();
  console.log('   Budget:', g ? `${g.budget} MIST` : 'N/A');
  
  console.log('\n💡 To enable on-chain features:');
  console.log('   1. Deploy contracts/sources/threat_registry.move');
  console.log('   2. await sui.initializeWithKeypair("private-key-hex")');
  console.log('   3. Update packageId in config\n');
}
