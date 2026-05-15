import { useTheme } from '../../hooks/useTheme';

interface LogoProps {
  /** force a specific theme for the logo, overriding auto-detection */
  forceTheme?: 'dark' | 'light';
  /** size in px (default 32) */
  size?: number;
  /** if a partner has uploaded a custom logo, prefer that and ignore theme */
  partnerLogoURL?: string | null;
  className?: string;
}

/**
 * Logo renders the ZAISHIELD VAULTSCAN emblem. It always picks the variant
 * that contrasts with the active theme — dark-mode → /logo-dark.svg
 * (Plasma White), light-mode → /logo-light.svg (Void Black). A partner
 * white-label logo, if configured, overrides everything.
 */
export function Logo({ forceTheme, size = 32, partnerLogoURL, className }: LogoProps) {
  const theme = useTheme();
  const active = forceTheme ?? theme;
  const src = partnerLogoURL && partnerLogoURL.length > 0
    ? partnerLogoURL
    : active === 'light' ? '/logo-light.svg' : '/logo-dark.svg';
  return (
    <img
      src={src}
      alt="ZAISHIELD VAULTSCAN"
      width={size} height={size}
      className={className}
      draggable={false}
    />
  );
}
