"use client";

import { useEffect, useCallback } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { apiClient } from '@/lib/api-client';
import { clearTokens, getTokens, setTokens } from '@/lib/auth';
import { useAuthStore } from '@/stores/auth-store';

type ApiError = {
  message?: string;
  response?: {
    data?: {
      detail?: string;
    };
  };
};

type LoginCredentials = {
  email: string;
  password: string;
};

type SignupPayload = LoginCredentials & {
  tenant_name: string;
  first_name: string;
  last_name: string;
};

function asApiError(error: unknown): ApiError {
  return error instanceof Error ? error : {};
}

export function useAuth() {
  const router = useRouter();
  const pathname = usePathname();
  const { user, setUser, isLoading, setIsLoading } = useAuthStore();

  const fetchUser = useCallback(async () => {
    try {
      if (!getTokens()?.accessToken) {
        throw new Error('No token');
      }
      const res = await apiClient.get('/auth/me');
      const user = res.data;
      setUser(user);
      return user;
    } catch (err: unknown) {
      const apiError = asApiError(err);
      if (apiError.message !== 'No token') {
        console.error("fetchUser error:", apiError.response?.data || apiError.message);
      }
      clearTokens();
      setUser(null);
      if (pathname && !pathname.startsWith('/login') && !pathname.startsWith('/signup')) {
        router.push('/login');
      }
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [setUser, setIsLoading, pathname, router]);

  useEffect(() => {
    // Only fetch if we haven't already, or if we are loading
    if (isLoading) {
      fetchUser().catch(() => {});
    }
  }, [fetchUser, isLoading]);

  const login = async (credentials: LoginCredentials) => {
    const res = await apiClient.post('/auth/login', credentials);
    if (res.data.mfa_required) {
      return { mfaRequired: true, mfaToken: res.data.mfa_token };
    }
    const bearerToken = res.data.access_token || res.data.api_key;
    if (!bearerToken) {
      throw new Error('Login failed: No bearer credential received.');
    }
    setTokens({
      accessToken: bearerToken,
      refreshToken: res.data.refresh_token,
    });
    await fetchUser();
    router.push('/overview');
    return { mfaRequired: false };
  };

  const verifyMfa = async (mfaToken: string, code: string) => {
    const res = await apiClient.post('/auth/login/mfa', { mfa_token: mfaToken, code });
    if (!res.data.access_token) {
      throw new Error('MFA verification failed: No access token received.');
    }
    setTokens({
      accessToken: res.data.access_token,
      refreshToken: res.data.refresh_token,
    });
    await fetchUser();
    router.push('/overview');
  };

  const signup = async (data: SignupPayload) => {
    const response = await apiClient.post('/onboarding/signup', {
      email: data.email,
      tenant_name: data.tenant_name,
    });
    throw new Error(
      `Email verification is required before login. Signup reference: ${response.data.signup_id}`
    );
  };

  const logout = () => {
    clearTokens();
    setUser(null);
    router.push('/login');
  };

  return { user, isLoading, login, verifyMfa, signup, logout };
}
