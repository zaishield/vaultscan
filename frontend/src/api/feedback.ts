// API client for §33 customer feedback loop.

import { api } from './client';

export interface FeedbackItem {
  id: string;
  category: 'bug' | 'feature' | 'question' | 'compliment' | 'complaint' | 'nps';
  severity: 'critical' | 'major' | 'minor' | 'cosmetic' | '';
  rating?: number;        // 0-10 NPS-style
  message: string;
  page_context?: string;
  status: 'new' | 'triaging' | 'planned' | 'in_progress' | 'resolved' | 'wont_fix';
  triaged_by?: string;
  triaged_at?: string;
  resolution?: string;
  submitted_at: string;
  user_email?: string;
}

export const feedback = {
  submit: (input: {
    category: FeedbackItem['category'];
    severity?: FeedbackItem['severity'];
    rating?: number;
    message: string;
    page_context?: string;
  }) => api.post<{ id: string }>(`/api/v1/feedback`, input),

  dismissNPS: () =>
    api.post<{ status: string }>(`/api/v1/feedback/dismiss-nps`),

  list: (status?: FeedbackItem['status']) => {
    const qs = status ? `?status=${status}` : '';
    return api.get<{ items: FeedbackItem[]; nps_score?: number }>(
      `/api/v1/feedback${qs}`);
  },

  triage: (id: string, input: {
    status: FeedbackItem['status'];
    resolution?: string;
  }) => api.patch<{ status: string }>(`/api/v1/feedback/${id}`, input),
};
