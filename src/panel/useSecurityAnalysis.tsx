import { useEffect, useState } from 'react';
import { SecurityOrchestrator } from '../engine/security/SecurityOrchestrator';

export function useSecurityAnalysis() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    let mounted = true;
    const orchestrator = new SecurityOrchestrator();

    orchestrator.analyze(document).then((result) => {
      if (!mounted) return;
      setData(result);
      setLoading(false);
    }).catch((err) => {
      if (!mounted) return;
      setError(err);
      setLoading(false);
    });

    return () => { mounted = false };
  }, []);

  return { data, loading, error };
}
