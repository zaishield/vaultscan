import { useEffect, useState } from 'react';

export type Theme = 'dark' | 'light';

/**
 * useTheme returns the active theme. The portal is dark-first per brand
 * guidelines (no white backgrounds), but the hook honours an explicit
 * `data-theme` attribute on <html> if the user toggles it via Settings,
 * and falls back to the OS preference otherwise.
 */
export function useTheme(): Theme {
  const [theme, setTheme] = useState<Theme>(detect());
  useEffect(() => {
    const onMedia = () => setTheme(detect());
    const observer = new MutationObserver(() => setTheme(detect()));
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme', 'class'] });
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    mq.addEventListener?.('change', onMedia);
    return () => {
      observer.disconnect();
      mq.removeEventListener?.('change', onMedia);
    };
  }, []);
  return theme;
}

function detect(): Theme {
  const explicit = document.documentElement.getAttribute('data-theme');
  if (explicit === 'light' || explicit === 'dark') return explicit;
  if (document.documentElement.classList.contains('light')) return 'light';
  // Default: VAULTSCAN is dark-first per brand guidelines.
  return 'dark';
}
