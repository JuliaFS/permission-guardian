export interface Badge {
  id: string;
  name: string;
  description: string;
  icon: string;
}

export interface QuizQuestion {
  id: string;
  text: string;
  options: string[];
  correctIndex: number;
  explanation: string;
}

export const QUIZ_QUESTIONS: QuizQuestion[] = [
  {
    id: 'q_typosquatting',
    text: 'Which URL is the official Google login page?',
    options: ['https://accounts.g00gle.com', 'https://accounts.google.com', 'http://google-login.net'],
    correctIndex: 1,
    explanation: 'Always check the spelling. "g00gle" uses zeros instead of letters, and "google-login.net" is a completely different domain.'
  },
  {
    id: 'q_https',
    text: 'What does the "S" in HTTPS stand for?',
    options: ['Standard', 'Secure', 'Static'],
    correctIndex: 1,
    explanation: 'HTTPS stands for Hypertext Transfer Protocol Secure. It means your connection to the site is encrypted.'
  },
  {
    id: 'q_permissions',
    text: 'Why is "Read and change all your data" a risky permission?',
    options: ['It slows down your computer', 'It can read passwords on any site you visit', 'It only works on Google sites'],
    correctIndex: 1,
    explanation: 'This permission allows an extension to see everything on the pages you visit, including passwords and banking info.'
  }
];

export const BADGE_DEFINITIONS: Badge[] = [
  { id: 'guardian_initiate', name: 'Guardian Initiate', description: 'Started your security journey', icon: '🛡️' },
  { id: 'privacy_pro', name: 'Privacy Pro', description: 'Maintain a security score above 90', icon: '💎' },
  { id: 'eagle_eye', name: 'Eagle Eye', description: 'Aced a security quiz', icon: '👁️' },
  { id: 'safe_surfer', name: 'Safe Surfer', description: 'No high-risk warnings for 3 days', icon: '🌊' }
];