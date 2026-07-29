import { useEffect, useState } from "react";
import { assetPath } from "../utils/paths";

export function useJson<T>(path: string, fallback: T): T {
  const [data, setData] = useState<T>(fallback);

  useEffect(() => {
    let mounted = true;

    fetch(assetPath(path))
      .then(response => (response.ok ? response.json() : fallback))
      .then((payload: T) => {
        if (mounted) setData(payload);
      })
      .catch(() => {
        if (mounted) setData(fallback);
      });

    return () => {
      mounted = false;
    };
  }, [fallback, path]);

  return data;
}
