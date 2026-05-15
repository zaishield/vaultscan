// Thin fetch wrapper. Adds auth token and tenant header automatically.

import { useAuthStore } from '../store/auth';

const API_BASE = '';  // proxied by Vite to backend

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const { token, tenantId } = useAuthStore.getState();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init.headers as Record<string, string> | undefined),
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (tenantId) headers['X-Tenant-Id'] = tenantId;
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  const text = await res.text();
  let body: unknown;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  if (!res.ok) {
    const msg = (body as { error?: { message?: string } } | null)?.error?.message
      ?? (typeof body === 'string' ? body : `HTTP ${res.status}`);
    throw new Error(msg);
  }
  return body as T;
}

export const api = {
  get:    <T,>(p: string)              => request<T>(p),
  post:   <T,>(p: string, body?: unknown) => request<T>(p, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined }),
  put:    <T,>(p: string, body?: unknown) => request<T>(p, { method: 'PUT',  body: body !== undefined ? JSON.stringify(body) : undefined }),
  patch:  <T,>(p: string, body?: unknown) => request<T>(p, { method: 'PATCH',body: body !== undefined ? JSON.stringify(body) : undefined }),
  delete: <T,>(p: string)              => request<T>(p, { method: 'DELETE' }),
  raw:    request,
};
