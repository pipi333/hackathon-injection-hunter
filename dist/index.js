/**
 * Injection Hunter - Main Entry Point
 *
 * AI Prompt Injection Detector for OpenClaw
 * Hackathon 2026 - Track 1: Safety & Security
 */
import { InjectionHunter } from './injection-hunter.js';
// Initialize with demo config
const hunter = new InjectionHunter({
    enableRegexScan: true,
    enableBlacklistCheck: true,
    enableSemanticAnalysis: true,
    autoQuarantine: false,
    logLevel: 'info'
});
export { hunter, InjectionHunter };
export * from './types.js';
