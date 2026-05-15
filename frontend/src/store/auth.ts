import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface AuthState {
  token: string | null;
  email: string | null;
  fullName: string | null;
  roles: string[];
  partnerId: string | null;
  tenantId: string | null;
  setSession: (s: Partial<AuthState>) => void;
  clear: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null, email: null, fullName: null, roles: [],
      partnerId: null, tenantId: null,
      setSession: (s) => set(s),
      clear: () => set({ token: null, email: null, fullName: null, roles: [],
                         partnerId: null, tenantId: null }),
    }),
    { name: 'vaultscan-session' },
  ),
);
