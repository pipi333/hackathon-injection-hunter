/**
 * Injection Hunter - Core Type Definitions
 */

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface ScanResult {
  risk: RiskLevel;
  score: number; // 0-100
  threats: Threat[];
  timestamp: string;
  input: string;
}

export interface Threat {
  type: string;
  pattern?: string;
  description: string;
  matchedText?: string;
  position: {
    start: number;
    end: number;
  };
}

export interface InjectionPattern {
  name: string;
  category: 'jailbreak' | 'prompt_leak' | 'system_override' | 'context_manipulation' | 'roleplay_escape' | 'obfuscation';
  severity: RiskLevel;
  regex: RegExp;  // Changed from string to RegExp
  description: string;
}

export interface BlacklistEntry {
  id: string;
  pattern: string;
  category: string;
  addedAt: string;
  source: string;
  matchCount: number;
}

export interface SecurityConfig {
  enableRegexScan: boolean;
  enableBlacklistCheck: boolean;
  enableSemanticAnalysis: boolean;
  autoQuarantine: boolean;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

// Sui Integration Types
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
  txDigest?: string;
}
