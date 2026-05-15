// API client for §34 partner-integration marketplace.

import { api } from './client';

export interface MarketplaceListing {
  id: string;
  slug: string;
  name: string;
  publisher: string;
  category: string;          // chat | ticketing | siem | devops | identity | incident
  description: string;
  integration_type: string;  // slack | jira | servicenow | ...
  config_schema: Record<string, unknown>; // JSON Schema
  docs_url?: string;
  logo_url?: string;
  verified: boolean;
}

export interface MarketplaceInstall {
  id: string;
  listing_name: string;
  listing_slug: string;
  category: string;
  integration_type: string;
  state: 'pending_config' | 'active' | 'suspended';
  installed_at: string;      // RFC3339
  integration_id?: string;
}

export const marketplace = {
  listListings: (category?: string) => {
    const qs = category ? `?category=${encodeURIComponent(category)}` : '';
    return api.get<{ listings: MarketplaceListing[] }>(`/api/v1/marketplace/listings${qs}`);
  },
  listInstalls: () =>
    api.get<{ installs: MarketplaceInstall[] }>(`/api/v1/marketplace/installs`),
  install: (input: {
    listing_id?: string; listing_slug?: string;
    label?: string; config?: Record<string, unknown>;
  }) =>
    api.post<{ install_id: string; integration_id: string; state: string }>(
      `/api/v1/marketplace/installs`, input),
  configure: (installID: string, config: Record<string, unknown>) =>
    api.patch<{ state: string }>(
      `/api/v1/marketplace/installs/${installID}`, { config }),
  uninstall: (installID: string) =>
    api.delete<{ state: string }>(`/api/v1/marketplace/installs/${installID}`),
};
