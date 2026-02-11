/**
 * Blacklist-based Pattern Matcher
 *
 * Loads and checks against a dynamically updating blacklist
 * stored in MEMORY.md format for easy OpenClaw integration.
 */
import type { BlacklistEntry, Threat } from './types.js';
export declare class BlacklistChecker {
    private blacklist;
    private blacklistPath;
    constructor(blacklistPath?: string);
    private loadBlacklist;
    scan(input: string): Threat[];
    addEntry(entry: Omit<BlacklistEntry, 'id' | 'addedAt' | 'matchCount'>): string;
    removeEntry(id: string): boolean;
    getBlacklist(): BlacklistEntry[];
    size(): number;
    private saveBlacklist;
    createDefaultBlacklist(): void;
}
