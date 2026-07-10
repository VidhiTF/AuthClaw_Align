export interface Tokens {
  accessToken: string;
  refreshToken?: string;
}

export function setTokens(tokens: Tokens) {
  if (typeof window !== 'undefined') {
    localStorage.setItem('authclaw_tokens', JSON.stringify(tokens));
  }
}

export function getTokens(): Tokens | null {
  if (typeof window !== 'undefined') {
    const stored = localStorage.getItem('authclaw_tokens');
    return stored ? JSON.parse(stored) : null;
  }
  return null;
}

export function clearTokens() {
  if (typeof window !== 'undefined') {
    localStorage.removeItem('authclaw_tokens');
  }
}

export function isAuthenticated(): boolean {
  return !!getTokens()?.accessToken;
}
