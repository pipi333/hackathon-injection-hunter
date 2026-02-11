/**
 * Blacklist-based Pattern Matcher
 * 
 * Loads and checks against a dynamically updating blacklist
 * stored in MEMORY.md format for easy OpenClaw integration.
 */

import fs from 'fs';
import path from 'path';
import type { BlacklistEntry, Threat } from './types.js';

const DEFAULT_BLACKLIST_PATH = './memory/blacklist.json';

export class BlacklistChecker {
  private blacklist: Map<string, BlacklistEntry> = new Map();
  private blacklistPath: string;
  
  constructor(blacklistPath?: string) {
    this.blacklistPath = blacklistPath || DEFAULT_BLACKLIST_PATH;
    this.loadBlacklist();
  }
  
  private loadBlacklist(): void {
    try {
      if (fs.existsSync(this.blacklistPath)) {
        const content = fs.readFileSync(this.blacklistPath, 'utf-8');
        const entries: BlacklistEntry[] = JSON.parse(content);
        
        for (const entry of entries) {
          this.blacklist.set(entry.id, entry);
        }
        
        console.log(`[Blacklist] Loaded ${this.blacklist.size} entries`);
      }
    } catch (e) {
      console.warn('[Blacklist] Could not load blacklist:', e);
    }
  }
  
  public scan(input: string): Threat[] {
    const threats: Threat[] = [];
    
    for (const [id, entry] of this.blacklist) {
      const regex = new RegExp(entry.pattern, 'gi');
      let match: RegExpExecArray | null;
      
      while ((match = regex.exec(input)) !== null) {
        threats.push({
          type: 'blacklist_match',
          pattern: id,
          description: `Blacklisted pattern: ${entry.category}`,
          matchedText: match[0],
          position: {
            start: match.index,
            end: match.index + match[0].length
          }
        });
        
        // Update match count
        entry.matchCount++;
        this.saveBlacklist();
      }
    }
    
    return threats;
  }
  
  public addEntry(entry: Omit<BlacklistEntry, 'id' | 'addedAt' | 'matchCount'>): string {
    const id = `bl_${Date.now()}`;
    const fullEntry: BlacklistEntry = {
      ...entry,
      id,
      addedAt: new Date().toISOString(),
      matchCount: 0
    };
    
    this.blacklist.set(id, fullEntry);
    this.saveBlacklist();
    
    return id;
  }
  
  public removeEntry(id: string): boolean {
    const removed = this.blacklist.delete(id);
    if (removed) {
      this.saveBlacklist();
    }
    return removed;
  }
  
  public getBlacklist(): BlacklistEntry[] {
    return Array.from(this.blacklist.values());
  }
  
  public size(): number {
    return this.blacklist.size;
  }
  
  private saveBlacklist(): void {
    try {
      const entries = Array.from(this.blacklist.values());
      
      // Ensure directory exists
      const dir = path.dirname(this.blacklistPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      fs.writeFileSync(this.blacklistPath, JSON.stringify(entries, null, 2));
    } catch (e) {
      console.error('[Blacklist] Could not save:', e);
    }
  }
  
  // Create default blacklist for demo
  public createDefaultBlacklist(): void {
    const defaults: Omit<BlacklistEntry, 'id' | 'addedAt' | 'matchCount'>[] = [
      {
        pattern: '(?:\\$|€|£|¥).*secret.*key',
        category: 'financial_secrets',
        source: 'demo'
      },
      {
        pattern: '(?:api|openai|anthropic|.*)[-_]key',
        category: 'api_keys',
        source: 'demo'
      },
      {
        pattern: '(?:password|passwd|pwd).*[=:].*',
        category: 'credentials',
        source: 'demo'
      },
      {
        pattern: 'mongo.*(?:url|connection)',
        category: 'database',
        source: 'demo'
      }
    ];
    
    for (const entry of defaults) {
      this.addEntry(entry);
    }
    
    console.log('[Blacklist] Created default entries');
  }
}
