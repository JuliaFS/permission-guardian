export interface BehavioralSignal {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  action?: string;
}

export interface BehavioralMetrics {
  score: number;
  habits: string[];
  suggestions: string[];
  siteSignals?: BehavioralSignal[]; // Нови сигнали от текущия сайт
}

/**
 * Анализира както историческите данни на потребителя, така и поведението на текущия сайт.
 */
export async function analyzeBehavior(): Promise<BehavioralMetrics> {
  const api = (globalThis as any).chrome ?? (globalThis as any).browser;
  const storage = api?.storage?.local;

  // Инициализация на резултатите
  const habits: string[] = [];
  const suggestions: string[] = [];
  let score = 100;

  // --- ЛОГИКА А: Анализ на сайта в реално време (Нова част) ---
  const siteSignals = analyzeCurrentSite();
  siteSignals.forEach(signal => {
    if (signal.severity === 'medium') score -= 10;
    if (signal.severity === 'low') score -= 5;
    habits.push(signal.description);
    // Добавяме специфичен съвет за всеки сигнал от сайта
    if (signal.id === 'dark_pattern_urgency') suggestions.push("Не се подвеждайте по таймери за обратно броене или надписи 'последна бройка'.");
    if (signal.id === 'high_third_party_load') suggestions.push("Използвайте AdBlocker, за да ограничите проследяването от трети страни.");
  });

  // --- ЛОГИКА Б: Анализ на историческите данни на потребителя (Твоята логика) ---
  if (storage) {
    const data = await storage.get(['pg_permission_history', 'pg_install_history']);
    const permHistory = data.pg_permission_history || [];
    const installHistory = data.pg_install_history || [];

    // 1. Процент на приемане
    const requests = permHistory.filter((h: any) => h.action === 'requested').length;
    const allowed = permHistory.filter((h: any) => h.action === 'allowed').length;
    const allowRate = requests > 0 ? (allowed / requests) : 0;

    if (allowRate > 0.8 && requests > 5) {
      score -= 20;
      habits.push("Приемате почти всички заявки за достъп.");
      suggestions.push("Бъдете по-критични. Не всеки сайт има нужда от камера или локация.");
    }

    // 2. Скорост на реакция (под 1.2 сек)
    const fastClicks = permHistory.filter((h: any) => h.action === 'allowed' && h.responseTime && h.responseTime < 1200).length;
    if (fastClicks >= 2) {
      score -= 15;
      habits.push("Кликвате върху 'Позволи' твърде бързо.");
      suggestions.push("Отделете секунда, за да прочетете какво точно иска сайтът.");
    }

    // 3. Честота на инсталиране
    const oneDay = 24 * 60 * 60 * 1000;
    const recentInstalls = installHistory.filter((h: any) => Date.now() - h.timestamp < oneDay).length;
    if (recentInstalls > 3) {
      score -= 15;
      habits.push("Инсталирали сте много разширения наведнъж.");
      suggestions.push("Премахнете разширенията, които не сте ползвали в последния месец.");
    }
  }

  return { 
    score: Math.max(0, score), 
    habits, 
    suggestions,
    siteSignals 
  };
}

/**
 * Помощна функция за анализ на текущия DOM (Dark Patterns & Scripts)
 */
function analyzeCurrentSite() {
  const signals = [];
  
  // 1. Проверка за Dark Patterns (Изкуствена спешност)
  const urgencyRegex = /(last chance|only \d left|оставащ|последна възможност|expires in)/i;
  const hasUrgency = urgencyRegex.test(document.body.innerText);
  
  if (hasUrgency) {
    signals.push({ 
      id: 'dark_pattern_urgency', 
      severity: 'medium' as const, 
      description: 'Сайтът използва трикове за спешност (Dark Patterns).' 
    });
  }

  // 2. Проверка за натовареност от трети страни (Тракери)
  const scripts = Array.from(document.scripts);
  const currentHost = window.location.hostname;
  const thirdPartyScripts = scripts.filter(s => s.src && !s.src.includes(currentHost));

  if (thirdPartyScripts.length > 15) {
    signals.push({ 
      id: 'high_third_party_load', 
      severity: 'low' as const, 
      description: `Засечени са ${thirdPartyScripts.length} външни скрипта (възможно проследяване).` 
    });
  }

  return signals;
}

// export interface BehavioralMetrics {
//   score: number;
//   habits: string[];
//   suggestions: string[];
// }

// /**
//  * Analyzes historical logs to identify risky user behaviors and calculate a security score.
//  */
// export async function analyzeBehavior(): Promise<BehavioralMetrics> {
//   const storage = (globalThis as any).chrome?.storage?.local ?? (globalThis as any).browser?.storage?.local;
//   if (!storage) return { score: 100, habits: [], suggestions: [] };

//   const data = await storage.get(['pg_permission_history', 'pg_install_history']);
//   const permHistory = data.pg_permission_history || [];
//   const installHistory = data.pg_install_history || [];

//   const habits: string[] = [];
//   const suggestions: string[] = [];
//   let score = 100;

//   // 1. Analyze Permission Acceptance Rate (Always accepting)
//   const requests = permHistory.filter((h: any) => h.action === 'requested').length;
//   const allowed = permHistory.filter((h: any) => h.action === 'allowed').length;
//   const allowRate = requests > 0 ? (allowed / requests) : 0;

//   if (allowRate > 0.8 && requests > 5) {
//     score -= 20;
//     habits.push("You tend to accept permissions without reviewing them");
//     suggestions.push("Be more selective. Not every site needs camera or location access.");
//   }

//   // 2. Analyze Reaction Speed (Clicking Allow too fast - under 1.2s)
//   const fastClicks = permHistory.filter((h: any) => h.action === 'allowed' && h.responseTime && h.responseTime < 1200).length;
//   if (fastClicks >= 2) {
//     score -= 15;
//     habits.push("Clicking 'Allow' too fast");
//     suggestions.push("Take a moment to read permission requests before clicking Allow.");
//   }

//   // 3. Extension Install Frequency
//   const oneDay = 24 * 60 * 60 * 1000;
//   const recentInstalls = installHistory.filter((h: any) => Date.now() - h.timestamp < oneDay).length;
//   if (recentInstalls > 3) {
//     score -= 15;
//     habits.push("Installing many extensions in a short period");
//     suggestions.push("Only install extensions you actually need to reduce your attack surface.");
//   }

//   return { 
//     score: Math.max(0, score), 
//     habits, 
//     suggestions 
//   };
// }