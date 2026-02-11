/**
 * Injection Hunter - Main Entry Point
 *
 * AI Prompt Injection Detector for OpenClaw
 * Hackathon 2026 - Track 1: Safety & Security
 *
 * Features:
 * - Multi-layer injection detection
 * - Risk assessment (0-100)
 * - Sui blockchain integration for audit proofs
 */
import { InjectionHunter } from './injection-hunter.js';
import { SuiIntegration, demoSuiIntegration } from './sui-integration.js';
// Initialize with demo config
const hunter = new InjectionHunter({
    enableRegexScan: true,
    enableBlacklistCheck: true,
    enableSemanticAnalysis: true,
    autoQuarantine: false,
    logLevel: 'info'
});
// Initialize Sui integration
const sui = new SuiIntegration();
export { hunter, sui, demoSuiIntegration, InjectionHunter };
export * from './types.js';
