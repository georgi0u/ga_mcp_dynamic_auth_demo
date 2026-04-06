const rawApiBase = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";
const rawWsBase = process.env.NEXT_PUBLIC_WS_BASE_URL ?? rawApiBase.replace(/^http/i, "ws");

export const API_BASE_URL = rawApiBase.replace(/\/$/, "");
export const WS_BASE_URL = rawWsBase.replace(/\/$/, "");
export const API_ORIGIN = new URL(API_BASE_URL).origin;
export const TOKEN_STORAGE_KEY = "mcp-auth-demo-token";

type RequestOptions = RequestInit & {
  token?: string;
};

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("Content-Type", "application/json");
  if (options.token) {
    headers.set("Authorization", `Bearer ${options.token}`);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let message = response.statusText;
    try {
      const payload = (await response.json()) as { error?: string };
      if (payload.error) {
        message = payload.error;
      }
    } catch {
      // Ignore JSON parse errors for non-JSON failures.
    }
    throw new Error(message);
  }

  return (await response.json()) as T;
}

