import type { Signal } from './types';

export class RiskEngine {
  compute(signals: Signal[]) {
    // 0 points means perfectly clean (Zero Risk Found)
    if (!signals || signals.length === 0) {
      return { score: 0, level: this.getLevel(0) };
    }

    const categoryDeductions: Record<string, number> = {
      'Sensitive Data': 0,
      'Website Security': 0,
      'Tracking & Storage': 0,
      'Website Reputation': 0,
    };

    const categoryCaps: Record<string, number> = {
      'Sensitive Data': 80,     
      'Website Security': 90,   
      'Tracking & Storage': 25, 
      'Website Reputation': 40, 
    };

    let criticalOverride = false;

    signals.forEach(s => {
      const impact = s.severity * s.confidence;
      const category = s.category || 'Tracking & Storage';

      if (impact >= 90) {
        criticalOverride = true;
      }

      if (categoryDeductions[category] !== undefined) {
        categoryDeductions[category] += impact;
      } else {
        categoryDeductions['Tracking & Storage'] += impact;
      }
    });

    // Accumulate risk points up from 0
    let accumulatedRisk = 0;
    for (const cat in categoryDeductions) {
      const cappedRisk = Math.min(categoryDeductions[cat], categoryCaps[cat]);
      accumulatedRisk += cappedRisk;
    }

    // Critical Overrides force the danger meter straight to the top zone
    if (criticalOverride) {
      accumulatedRisk = Math.max(accumulatedRisk, 95); // 95/100 points of danger!
    }

    const boundedRiskScore = Math.max(0, Math.min(100, Math.round(accumulatedRisk)));

    return {
      score: boundedRiskScore, // HIGH number = HIGH danger
      level: this.getLevel(boundedRiskScore),
    };
  }

  private getLevel(score: number) {
    // 0 to 30 is Low Danger (Green)
    if (score <= 30) return 'low-risk';     
    // 31 to 79 is Medium Danger (Orange)
    if (score <= 79) return 'medium-risk';  
    // 80 to 100 is High Danger (Red)
    return 'high-risk';                     
  }
}

// import type { Signal } from './types';

// export class RiskEngine {
//   compute(signals: Signal[]) {
//     // 0 points means absolute pristine security (Zero Risk Found)
//     if (!signals || signals.length === 0) {
//       return { score: 0, level: this.getLevel(0) };
//     }

//     // Category caps accumulate penalty points toward a ceiling of 100
//     const categoryDeductions: Record<string, number> = {
//       'Sensitive Data': 0,
//       'Website Security': 0,
//       'Tracking & Storage': 0,
//       'Website Reputation': 0,
//     };

//     const categoryCaps: Record<string, number> = {
//       'Sensitive Data': 80,     // Raw inputs or missing sandboxes can add up to 80 risk points
//       'Website Security': 90,   // External untrusted form routes can add up to 90 risk points
//       'Tracking & Storage': 25, // Hundreds of cookies or localstorage items cap out at 25 risk points total
//       'Website Reputation': 40, // Suspicious scripts max out at 40 risk points
//     };

//     let criticalOverride = false;

//     // Map your custom signals array
//     signals.forEach(s => {
//       // severity * confidence determines the raw base impact
//       const impact = s.severity * s.confidence;
//       const category = s.category || 'Tracking & Storage';

//       // If a single vulnerability is catastrophic, trigger a critical risk override
//       if (impact >= 90) {
//         criticalOverride = true;
//       }

//       if (categoryDeductions[category] !== undefined) {
//         categoryDeductions[category] += impact;
//       } else {
//         categoryDeductions['Tracking & Storage'] += impact;
//       }
//     });

//     // Accumulate the capped risk vectors
//     let accumulatedRisk = 0;
//     for (const cat in categoryDeductions) {
//       const cappedRisk = Math.min(categoryDeductions[cat], categoryCaps[cat]);
//       accumulatedRisk += cappedRisk;
//     }

//     // Critical Overrides lock the meter into high alert zones immediately
//     if (criticalOverride) {
//       accumulatedRisk = Math.max(accumulatedRisk, 85);
//     }

//     // Bound the final score strictly between 0 and 100
//     const boundedRiskScore = Math.max(0, Math.min(100, Math.round(accumulatedRisk)));

//     return {
//       score: boundedRiskScore,
//       level: this.getLevel(boundedRiskScore),
//     };
//   }

//   private getLevel(score: number) {
//     // Risk increments ascending from 0 to 100
//     if (score <= 30) return 'low-risk';     // 0 - 30   -> Green zone (Safe)
//     if (score <= 65) return 'medium-risk';  // 31 - 65  -> Orange zone (Suspicious)
//     return 'high-risk';                     // 66 - 100 -> Red zone (Dangerous)
//   }
// }

// import type { Signal } from './types';

// export class RiskEngine {
//   compute(signals: Signal[]) {
//     if (!signals || signals.length === 0) {
//       return { score: 100, level: this.getLevel(100) };
//     }

//     const weighted = signals.map(s => s.severity * s.confidence);

//     const score = 100 - (weighted.reduce((a, b) => a + b, 0) / Math.max(1, signals.length));

//     const bounded = Math.max(0, Math.min(100, Math.round(score)));

//     return {
//       score: bounded,
//       level: this.getLevel(bounded),
//     };
//   }

//   private getLevel(score: number) {
//     if (score >= 70) return 'low-risk';
//     if (score >= 30) return 'medium-risk';
//     return 'high-risk';
//   }
// }
