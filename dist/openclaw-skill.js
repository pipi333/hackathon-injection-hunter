/**
 * OpenClaw Skill Integration
 *
 * This skill enables OpenClaw agents to scan external inputs
 * for prompt injection attacks before processing.
 */
import { InjectionHunter } from './injection-hunter.js';
import { SuiIntegration } from './sui-integration.js';
// Create singleton instances
let hunterInstance = null;
let suiInstance = null;
function getHunter() {
    if (!hunterInstance) {
        hunterInstance = new InjectionHunter({
            enableRegexScan: true,
            enableBlacklistCheck: true,
            enableSemanticAnalysis: true,
            autoQuarantine: false,
            logLevel: 'info'
        });
    }
    return hunterInstance;
}
function getSui() {
    if (!suiInstance) {
        suiInstance = new SuiIntegration();
    }
    return suiInstance;
}
const INJECTION_HUNTER_SKILL = {
    name: 'injection-hunter',
    description: 'Scan external inputs for prompt injection attacks',
    parameters: {
        input: {
            type: 'string',
            description: 'The input text to scan for injection attacks'
        },
        autoQuarantine: {
            type: 'boolean',
            description: 'Automatically quarantine critical threats',
            default: false
        }
    },
    async scan(input, autoQuarantine = false) {
        const hunter = getHunter();
        const { result, quarantined } = await hunter.scanAndQuarantine(input);
        return {
            success: true,
            risk: result.risk,
            score: result.score,
            threats: result.threats,
            quarantined,
            message: this.getActionMessage(result.risk, quarantined)
        };
    },
    getActionMessage(risk, quarantined) {
        switch (risk) {
            case 'critical':
                return quarantined
                    ? '🚨 CRITICAL THREAT DETECTED AND QUARANTINED'
                    : '🚨 CRITICAL THREAT DETECTED - Review required';
            case 'high':
                return '⚠️ HIGH RISK - Manual review recommended';
            case 'medium':
                return '📝 MEDIUM RISK - Flagged for review';
            default:
                return '✅ LOW RISK - Input safe to process';
        }
    },
    getStatistics() {
        return getHunter().getStatistics();
    },
    addToBlacklist(pattern, category) {
        return getHunter().addToBlacklist(pattern, category, 'openclaw-agent');
    },
    getLogs(limit = 50) {
        return getHunter().getLogs(limit);
    },
    configure(options) {
        getHunter().updateConfig({
            enableRegexScan: options.enableRegex ?? true,
            enableBlacklistCheck: options.enableBlacklist ?? true,
            enableSemanticAnalysis: options.enableSemantic ?? true,
            autoQuarantine: options.autoQuarantine ?? false
        });
        return { success: true, message: 'Configuration updated' };
    },
    // Sui blockchain integration methods
    async createOnChainProof(scanResult) {
        const sui = getSui();
        const proof = sui.createScanProof(`scan_${Date.now()}`, scanResult.risk, scanResult.threats);
        return {
            success: true,
            proof,
            message: 'Proof created. Submit to Sui blockchain to finalize.'
        };
    },
    async verifyOnChainProof(proofId) {
        const sui = getSui();
        return sui.getProofFromChain(proofId);
    }
};
export default INJECTION_HUNTER_SKILL;
