import type { Signal } from './types';

export class SignalDetector {
  detectPageSignals(doc: Document): Signal[] {
    const results: Signal[] = [];

    const urgency = this.detectUrgency(doc);
    if (urgency) results.push(urgency);

    const phishing = this.detectPhishingPatterns(doc);
    if (phishing) results.push(phishing as Signal);

    const thirdParty = this.detectThirdPartyScripts(doc);
    if (thirdParty) results.push(thirdParty);

    return results.filter(Boolean);
  }

  private detectUrgency(doc: Document): Signal | null {
    const text = doc.body?.innerText ?? '';

    const patterns = [
      { regex: /only\s+\d+\s+left/i, weight: 70 },
      { regex: /expires in/i, weight: 60 },
      { regex: /(last chance|last opportunity|limited time)/i, weight: 65 },
    ];

    const match = patterns.find(p => p.regex.test(text));
    if (!match) return null;

    return {
      id: 'urgency_pattern',
      type: 'page',
      category: 'dark_pattern',
      severity: match.weight,
      confidence: 0.6,
      source: 'dom',
      metadata: { snippet: text.slice(0, 300) },
      timestamp: Date.now(),
    };
  }

  private detectPhishingPatterns(doc: Document): Signal | null {
    const url = doc.location?.href ?? '';
    // simple heuristics
    if (/@/.test(url)) {
      return {
        id: 'url_at_symbol',
        type: 'page',
        category: 'phishing',
        severity: 50,
        confidence: 0.6,
        source: 'dom',
        metadata: { url },
        timestamp: Date.now(),
      };
    }
    if (url.length > 200) {
      return {
        id: 'url_length',
        type: 'page',
        category: 'phishing',
        severity: 40,
        confidence: 0.5,
        source: 'dom',
        metadata: { urlLength: url.length },
        timestamp: Date.now(),
      };
    }
    return null;
  }

  private detectThirdPartyScripts(doc: Document): Signal | null {
    const scripts = Array.from(doc.scripts || [] as any[]);
    const host = doc.location?.hostname ?? (typeof window !== 'undefined' ? window.location.hostname : '');

    const external = scripts.filter(s => s.src && !s.src.includes(host));

    const ratio = external.length / Math.max(1, scripts.length);

    if (ratio < 0.3) return null;

    return {
      id: 'third_party_heavy',
      type: 'page',
      category: 'tracking',
      severity: Math.min(90, Math.round(ratio * 100)),
      confidence: 0.8,
      source: 'dom',
      metadata: { externalCount: external.length, total: scripts.length },
      timestamp: Date.now(),
    };
  }
}
