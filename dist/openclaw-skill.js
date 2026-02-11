/**
 * OpenClaw Skill Integration
 *
 * This skill enables OpenClaw agents to scan external inputs
 * for prompt injection attacks before processing.
 */
import { hunter } from './index.js';
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
        return hunter.getStatistics();
    },
    addToBlacklist(pattern, category) {
        return hunter.addToBlacklist(pattern, category, 'openclaw-agent');
    },
    getLogs(limit = 50) {
        return hunter.getLogs(limit);
    },
    configure(options) {
        hunter.updateConfig({
            enableRegexScan: options.enableRegex ?? true,
            enableBlacklistCheck: options.enableBlacklist ?? true,
            enableSemanticAnalysis: options.enableSemantic ?? true,
            autoQuarantine: options.autoQuarantine ?? false
        });
        return { success: true, message: 'Configuration updated' };
    }
};
export default INJECTION_HUNTER_SKILL;
