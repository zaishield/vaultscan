import { create } from 'zustand';
import type { Branding } from '../types';
import { api } from '../api/client';

interface BrandingState {
  bundle: Branding | null;
  loading: boolean;
  error: string | null;
  load: () => Promise<void>;
}

export const useBranding = create<BrandingState>((set) => ({
  bundle: null,
  loading: false,
  error: null,
  load: async () => {
    set({ loading: true, error: null });
    try {
      const bundle = await api.get<Branding>(`/api/v1/branding?domain=${encodeURIComponent(location.hostname)}`);
      set({ bundle, loading: false });
      // Inject CSS variables for partner-specific overrides on top of brand defaults.
      document.documentElement.style.setProperty('--brand-primary',   bundle.branding.primary_color   || '#FF6B00');
      document.documentElement.style.setProperty('--brand-secondary', bundle.branding.secondary_color || '#FF8C00');
      if (bundle.branding.product_name) document.title = bundle.branding.product_name;
    } catch (e) {
      set({ error: (e as Error).message, loading: false });
    }
  },
}));
