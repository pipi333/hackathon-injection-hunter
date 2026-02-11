/**
 * Audit Logger - Records all scan results for security review
 */
import fs from 'fs';
import path from 'path';
const DEFAULT_LOG_PATH = './logs/audit.json';
export class AuditLogger {
    logPath;
    logs = [];
    constructor(logPath) {
        this.logPath = logPath || DEFAULT_LOG_PATH;
        this.loadLogs();
        this.ensureLogDir();
    }
    ensureLogDir() {
        const dir = path.dirname(this.logPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    }
    loadLogs() {
        try {
            if (fs.existsSync(this.logPath)) {
                const content = fs.readFileSync(this.logPath, 'utf-8');
                this.logs = JSON.parse(content);
                console.log(`[AuditLogger] Loaded ${this.logs.length} existing entries`);
            }
        }
        catch (e) {
            console.warn('[AuditLogger] Could not load logs:', e);
        }
    }
    log(input, risk, score, threats, action = 'logged') {
        const entry = {
            id: `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            timestamp: new Date().toISOString(),
            inputHash: this.hashInput(input),
            risk,
            score,
            threatCount: threats.length,
            threats,
            action
        };
        this.logs.unshift(entry); // Add to beginning
        // Keep only last 1000 entries in memory
        if (this.logs.length > 1000) {
            this.logs = this.logs.slice(0, 1000);
        }
        this.saveLogs();
        console.log(`[AuditLogger] Logged scan: ${risk} (score: ${score}), action: ${action}`);
    }
    getLogs(limit = 100) {
        return this.logs.slice(0, limit);
    }
    getLogsByRisk(risk) {
        return this.logs.filter(log => log.risk === risk);
    }
    getStatistics() {
        const byRisk = {};
        const threatTypes = {};
        for (const log of this.logs) {
            byRisk[log.risk] = (byRisk[log.risk] || 0) + 1;
            for (const threat of log.threats) {
                threatTypes[threat.type] = (threatTypes[threat.type] || 0) + 1;
            }
        }
        return {
            total: this.logs.length,
            byRisk,
            recentThreats: Object.entries(threatTypes)
                .map(([type, count]) => ({ type, count }))
                .sort((a, b) => b.count - a.count)
                .slice(0, 10)
        };
    }
    exportJson() {
        return JSON.stringify(this.logs, null, 2);
    }
    clear() {
        this.logs = [];
        this.saveLogs();
        console.log('[AuditLogger] Cleared all logs');
    }
    saveLogs() {
        try {
            fs.writeFileSync(this.logPath, JSON.stringify(this.logs, null, 2));
        }
        catch (e) {
            console.error('[AuditLogger] Could not save logs:', e);
        }
    }
    hashInput(input) {
        // Simple hash for identification without storing actual input
        let hash = 0;
        for (let i = 0; i < input.length; i++) {
            const char = input.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return Math.abs(hash).toString(16);
    }
}
