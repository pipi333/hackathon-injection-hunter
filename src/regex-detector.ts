/**
 * Regex-based Injection Pattern Detector
 * 
 * Detects common prompt injection patterns including:
 * - Jailbreak attempts (DAN, AIM, etc.)
 * - System prompt overrides
 * - Context manipulation
 * - Roleplay escapes
 */

import type { InjectionPattern, Threat } from './types.js';

const INJECTION_PATTERNS: InjectionPattern[] = [
  // === JAILBREAK PATTERNS ===
  {
    name: 'DAN_Mode',
    category: 'jailbreak',
    severity: 'critical',
    regex: /(?:^|\s)(DAN|Do Anything Now|Jailbreak|ignore.*previous.*instructions)/i,
    description: 'DAN (Do Anything Now) jailbreak attempt'
  },
  {
    name: 'AIM_Mode',
    category: 'jailbreak',
    severity: 'critical',
    regex: /(?:^|\s)(AIM|Always Intelligent Machiavellian)/i,
    description: 'AIM jailbreak pattern'
  },
  {
    name: 'Dev_Mode',
    category: 'jailbreak',
    severity: 'critical',
    regex: /(?:dev|developer).*(mode|override|bypass)/i,
    description: 'Developer mode bypass attempt'
  },
  {
    name: ' Jailbreak_Generic',
    category: 'jailbreak',
    severity: 'high',
    regex: /(?:jailbreak|bypass.*(security|safety|restriction)|ignore.*(rules|guidelines))/i,
    description: 'Generic jailbreak attempt'
  },
  
  // === SYSTEM OVERRIDE ===
  {
    name: 'System_Prompt_Override',
    category: 'system_override',
    severity: 'critical',
    regex: /(?:system.*prompt|instructions).*(=|:=|\+=|<=|replace|change|modify|set.*new)/i,
    description: 'System prompt override attempt'
  },
  {
    name: 'Role_Play_Escape',
    category: 'roleplay_escape',
    severity: 'high',
    regex: /(?:ignore.*(all.*previous|system|developer)|forget.*(everything|instructions|context)|break.*(character|role|out.*of.*character))/i,
    description: 'Roleplay/escape attempt'
  },
  {
    name: 'New_System_Prompt',
    category: 'system_override',
    severity: 'critical',
    regex: /(?:new.*system.*prompt|your.*new.*(role|personality)|from.*now.*on.*you.*are|act.*as.*if.*you.*were)/i,
    description: 'Attempt to assign new system prompt'
  },
  
  // === CONTEXT/MEMORY MANIPULATION ===
  {
    name: 'Memory_Override',
    category: 'context_manipulation',
    severity: 'high',
    regex: /(?:memory.*(override|replace|clear|delete)|remember.*(that.*is.*not|instead)|your.*memory.*(is|contains))/i,
    description: 'Memory/context manipulation attempt'
  },
  {
    name: 'History_Ignore',
    category: 'context_manipulation',
    severity: 'medium',
    regex: /(?:ignore.*(previous|history|conversation|context)|don.?t.*consider.*(earlier|above|previous))/i,
    description: 'Ignore conversation history attempt'
  },
  
  // === PROMPT LEAK ===
  {
    name: 'Prompt_Reveal',
    category: 'prompt_leak',
    severity: 'high',
    regex: /(?:reveal.*(system|prompt|instructions|configuration)|show.*(original|underlying).*(prompt|code)|print.*(your|the).*(system|prompt|instruction))/i,
    description: 'Prompt revelation attempt'
  },
  {
    name: 'Output_Specification',
    category: 'prompt_leak',
    severity: 'medium',
    regex: /(?:output.*(in.*(json|xml|markdown|code)|raw)|response.*format.*must.*(be|include)|response.*should.*(contain|include))/i,
    description: 'Specific output format manipulation'
  },
  
  // === SPECIAL CHARACTERS / ENCODING ===
  {
    name: 'Null_Byte_Injection',
    category: 'system_override',
    severity: 'high',
    regex: /[\x00-\x08\x0B\x0C\x0E-\x1F]/,
    description: 'Control character injection'
  },
  {
    name: 'Unicode_Zalgo',
    category: 'system_override',
    severity: 'medium',
    regex: /[\p{M}\p{Mn}\p{Mc}]{5,}/u,
    description: 'Unicode manipulation attempt'
  },
  
  // === EXTERNAL REFERENCES ===
  {
    name: 'Remote_Code_Execution',
    category: 'system_override',
    severity: 'critical',
    regex: /(?:execute|run|system\(|eval\(|__import__|os\.popen|subprocess)/i,
    description: 'Code execution attempt'
  },
  
  // === SOCIAL ENGINEERING ===
  {
    name: 'Urgency_Manipulation',
    category: 'context_manipulation',
    severity: 'low',
    regex: /(?:immediately|urgent|asap|right.*now.*must|emergency|critical.*that.*you.*do)/i,
    description: 'Urgency-based manipulation'
  },
  {
    name: 'Authority_Impersonation',
    category: 'context_manipulation',
    severity: 'medium',
    regex: /(?:as.*(your|the).*(admin|developer|owner|creator|master)|i.*am.*(authorized|admin|developer)|you.*must.*obey.*me)/i,
    description: 'Authority impersonation attempt'
  }
];

export class RegexDetector {
  private patterns: Map<string, RegExp> = new Map();
  
  constructor() {
    this.initializePatterns();
  }
  
  private initializePatterns(): void {
    for (const pattern of INJECTION_PATTERNS) {
      try {
        this.patterns.set(
          pattern.name, 
          new RegExp(pattern.regex, 'gi')
        );
      } catch (e) {
        console.warn(`Invalid regex pattern: ${pattern.name}`);
      }
    }
  }
  
  public scan(input: string): Threat[] {
    const threats: Threat[] = [];
    
    for (const [name, regex] of this.patterns) {
      const pattern = INJECTION_PATTERNS.find(p => p.name === name);
      if (!pattern) continue;
      
      // Reset regex state
      regex.lastIndex = 0;
      
      let match: RegExpExecArray | null;
      while ((match = regex.exec(input)) !== null) {
        threats.push({
          type: pattern.category,
          pattern: pattern.name,
          description: pattern.description,
          matchedText: match[0],
          position: {
            start: match.index,
            end: match.index + match[0].length
          }
        });
      }
    }
    
    return this.deduplicate(threats);
  }
  
  private deduplicate(threats: Threat[]): Threat[] {
    const seen = new Set<string>();
    return threats.filter(t => {
      const key = `${t.type}:${t.position.start}:${t.position.end}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
  
  public getPatternCount(): number {
    return this.patterns.size;
  }
  
  public listCategories(): string[] {
    const categories = new Set<string>();
    for (const pattern of INJECTION_PATTERNS) {
      categories.add(pattern.category);
    }
    return Array.from(categories);
  }
}
