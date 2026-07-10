"use client";

import { useState } from 'react';
import Link from 'next/link';
import { useAuth } from '@/hooks/use-auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';

type ApiError = {
  message?: string;
  response?: {
    data?: {
      detail?: string;
    };
  };
};

function getAuthErrorMessage(error: unknown, fallback: string) {
  const apiError = error as ApiError;
  return apiError.response?.data?.detail || apiError.message || fallback;
}

export default function LoginPage() {
  const { login, verifyMfa } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [mfaStep, setMfaStep] = useState(false);
  const [mfaToken, setMfaToken] = useState('');
  const [mfaCode, setMfaCode] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      const res = await login({ email, password });
      if (res?.mfaRequired) {
        setMfaToken(res.mfaToken);
        setMfaStep(true);
        toast.info('Please enter your MFA code');
      } else {
        toast.success('Login successful');
      }
    } catch (error: unknown) {
      const errorMsg = getAuthErrorMessage(error, 'Failed to login');
      if (errorMsg === 'Network Error') {
        toast.error('Backend server unreachable. Please check API connection.');
      } else {
        toast.error(errorMsg);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      await verifyMfa(mfaToken, mfaCode);
      toast.success('Login successful');
    } catch (error: unknown) {
      const errorMsg = getAuthErrorMessage(error, 'Invalid MFA code');
      if (errorMsg === 'Network Error') {
        toast.error('Backend server unreachable. Please check API connection.');
      } else {
        toast.error(errorMsg);
      }
    } finally {
      setLoading(false);
    }
  };

  if (mfaStep) {
    return (
      <div className="w-full">
        <form onSubmit={handleMfaSubmit} className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium text-neutral-300">Authenticator Code</label>
            <Input 
              type="text" 
              placeholder="000000" 
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600 text-center tracking-widest text-lg"
              required
              maxLength={6}
            />
            <p className="text-xs text-neutral-500">Enter the 6-digit code from your authenticator app.</p>
          </div>
          <Button 
            type="submit" 
            disabled={loading || mfaCode.length < 6}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium"
          >
            {loading ? 'Verifying...' : 'Verify & Sign In'}
          </Button>
          <Button 
            type="button" 
            variant="ghost"
            onClick={() => { setMfaStep(false); setMfaCode(''); }}
            className="w-full text-neutral-400 hover:text-white mt-2"
          >
            Back to login
          </Button>
        </form>
      </div>
    );
  }

  return (
    <div className="w-full">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <label className="text-sm font-medium text-neutral-300">Email Address</label>
          <Input 
            type="email" 
            placeholder="admin@authclaw.io" 
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600"
            required
          />
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-sm font-medium text-neutral-300">Password</label>
            <span className="text-xs text-neutral-500">Password reset is handled by your tenant admin.</span>
          </div>
          <div className="relative">
            <Input 
              type={showPassword ? "text" : "password"} 
              placeholder="********"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600 pr-10"
              required
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-neutral-500 hover:text-neutral-300"
              tabIndex={-1}
            >
              {showPassword ? (
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/></svg>
              ) : (
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
              )}
            </button>
          </div>
        </div>
        <Button 
          type="submit" 
          disabled={loading}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium"
        >
          {loading ? 'Signing in...' : 'Sign In'}
        </Button>
      </form>
      
      <div className="mt-6 text-center text-sm text-neutral-400">
        Don&apos;t have an account?{' '}
        <Link href="/signup" className="text-blue-500 hover:text-blue-400 font-medium">
          Create an organization
        </Link>
      </div>
    </div>
  );
}
