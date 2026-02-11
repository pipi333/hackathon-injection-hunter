/**
 * Regex-based Injection Pattern Detector
 * 
 * Detects common prompt injection patterns including:
 * - Jailbreak attempts (DAN, AIM, etc.)
 * - System prompt overrides
 * - Context manipulation
 * - Roleplay escapes
 * - Chinese injection patterns
 * - Emoji/Unicode manipulation
 * - Base64 encoding attacks
 */

import type { InjectionPattern, Threat } from './types.js';

const INJECTION_PATTERNS: InjectionPattern[] = [
  // === JAILBREAK PATTERNS (English) ===
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
    name: 'Jailbreak_Generic',
    category: 'jailbreak',
    severity: 'high',
    regex: /(?:jailbreak|bypass.*(security|safety|restriction)|ignore.*(rules|guidelines))/i,
    description: 'Generic jailbreak attempt'
  },
  {
    name: 'Roleplay_Jailbreak',
    category: 'jailbreak',
    severity: 'high',
    regex: /(?:character.*that.*(doesn\'t|does not).*follow.*(rules|guidelines)|act.*as.*an.*(evil|unethical|rogue).*(AI|assistant)|you.*are.*now.*(evil|evil AI|rogue))/i,
    description: 'Roleplay-based jailbreak'
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
  {
    name: 'Override_Start',
    category: 'system_override',
    severity: 'critical',
    regex: /(?:^|\n)(?:system|assistant|AI)[:\s]*(?:=|is|:)/im,
    description: 'System prompt injection at start'
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
    description: 'Unicode manipulation attempt (Zalgo)'
  },
  {
    name: 'Zero_Width_Injection',
    category: 'system_override',
    severity: 'medium',
    regex: /[\u200B-\u200D\uFEFF]/,
    description: 'Zero-width character injection'
  },
  
  // === BASE64 / ENCODING ATTACKS ===
  {
    name: 'Base64_Encode',
    category: 'obfuscation',
    severity: 'high',
    regex: /(?:base64|base.?64)[\s:]*([A-Za-z0-9+/]{20,}=*)/i,
    description: 'Base64 encoded content detected'
  },
  {
    name: 'Obfuscated_Command',
    category: 'obfuscation',
    severity: 'medium',
    regex: /(?:encode|decode|obfuscate|obfuscation).*(command|instruction|prompt)/i,
    description: 'Obfucation attempt mentioned'
  },
  {
    name: 'URL_Encode',
    category: 'obfuscation',
    severity: 'medium',
    regex: /%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}%[0-9A-Fa-f]{2}/,
    description: 'URL encoded content detected'
  },
  
  // === EXTERNAL REFERENCES ===
  {
    name: 'Remote_Code_Execution',
    category: 'system_override',
    severity: 'critical',
    regex: /(?:execute|run|system\(|eval\(|__import__|os\.popen|subprocess|exec\()/i,
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
  },
  
  // === CHINESE INJECTION PATTERNS ===
  {
    name: 'CN_Jailbreak',
    category: 'jailbreak',
    severity: 'critical',
    regex: /(?:越狱|DAN|无视.*(所有|前面).*(指令|规则|提示)|忽略.*(所有|前面).*(指令|规则|提示))/u,
    description: 'Chinese jailbreak attempt'
  },
  {
    name: 'CN_System_Override',
    category: 'system_override',
    severity: 'critical',
    regex: /(?:系统.*提示.*(更改|替换|修改)|新的.*(系统.*提示|角色|人格)|从现在开始.*你是)/u,
    description: 'Chinese system prompt override'
  },
  {
    name: 'CN_Memory_Override',
    category: 'context_manipulation',
    severity: 'high',
    regex: /(?:记忆.*(覆盖|清除|删除|修改)|忘记.*(所有|之前).*(内容|指令|上下文)|忽略.*(历史|上下文))/u,
    description: 'Chinese memory/context manipulation'
  },
  {
    name: 'CN_Prompt_Leak',
    category: 'prompt_leak',
    severity: 'high',
    regex: /(?:显示.*(系统.*提示|原始.*提示|指令)|泄露.*(系统.*提示|指令))/u,
    description: 'Chinese prompt leak attempt'
  },
  {
    name: 'CN_Ignore_History',
    category: 'context_manipulation',
    severity: 'medium',
    regex: /(?:忽略.*(之前|上面|历史).*(内容|对话|上下文)|不要.*考虑.*(之前|上面))/u,
    description: 'Chinese ignore history attempt'
  },
  
  // === EMOJI / VISUAL MANIPULATION ===
  {
    name: 'Emoji_Spamming',
    category: 'context_manipulation',
    severity: 'low',
    regex: /[\p{Emoji_Presentation}]{10,}/u,
    description: 'Excessive emoji usage'
  },
  {
    name: 'Hidden_Text',
    category: 'obfuscation',
    severity: 'medium',
    regex: /(?:[\p{Emoji_Presentation}]|\p{Extended_Pictographic})/u,
    description: 'Potential hidden text using emojis'
  },
  
  // === NEWLINE INJECTION ===
  {
    name: 'MultiLine_Override',
    category: 'system_override',
    severity: 'critical',
    regex: /(?:^|\n)[\s]*(?:system|instructions|prompt)[\s]*:/gim,
    description: 'Multi-line system prompt injection'
  },
  
  // === ADVANCED JAILBREAKS ===
  {
    name: 'Base64_Jailbreak',
    category: 'jailbreak',
    severity: 'critical',
    regex: /(?:[A-Za-z0-9+/]{50,}={0,2})/,
    description: 'Possible base64 encoded jailbreak'
  },
  {
    name: 'Character_Injection',
    category: 'obfuscation',
    severity: 'medium',
    regex: /(?:l\.\.?1\.\?i\.\?c\.\?e\.\?|s\.\?y\.\?s\.\?t\.\?e\.\?m\.\?|o\.\?v\.\?e\.\?r\.\?r\.\?i\.\?d\.\?e)/i,
    description: 'Character-spaced obfuscation'
  },
  {
    name: 'Homoglyph_Attack',
    category: 'obfuscation',
    severity: 'medium',
    regex: /[а-яА-ЯԀ-Ԃ]/u,
    description: 'Homoglyph/Cyrillic character detected'
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
          new RegExp(pattern.regex.source, pattern.regex.flags)
        );
      } catch (e) {
        console.warn(`Invalid regex pattern: ${pattern.name}`);
      }
    }
    console.log(`[RegexDetector] Loaded ${this.patterns.size} patterns`);
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
