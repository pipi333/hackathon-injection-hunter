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
declare const hunter: InjectionHunter;
declare const sui: SuiIntegration;
export { hunter, sui, demoSuiIntegration, InjectionHunter };
export * from './types.js';
