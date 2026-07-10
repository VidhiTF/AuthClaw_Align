"use client";

import { useState } from 'react';
import Link from 'next/link';
import { useAuth } from '@/hooks/use-auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';
// Removed lucide-react import for SVG replacement

type ApiError = {
  message?: string;
  response?: {
    data?: {
      detail?: string;
    };
  };
};

export default function SignupPage() {
  const { signup } = useAuth();
  const [formData, setFormData] = useState({
    tenant_name: '',
    email: '',
    password: '',
    first_name: '',
    last_name: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      await signup(formData);
      toast.success('Account created successfully');
    } catch (error: unknown) {
      const apiError = error as ApiError;
      const errorMsg = apiError.response?.data?.detail || 'Failed to sign up';
      if (apiError.message === 'Network Error') {
        toast.error('Backend server unreachable. Please check API connection.');
      } else {
        toast.error(errorMsg);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData(prev => ({...prev, [e.target.name]: e.target.value}));
  };

  return (
    <div className="w-full">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <label className="text-sm font-medium text-neutral-300">Organization Name</label>
          <Input 
            name="tenant_name"
            placeholder="Acme Corp" 
            value={formData.tenant_name}
            onChange={handleChange}
            className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600"
            required
          />
        </div>
        
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-sm font-medium text-neutral-300">First Name</label>
            <Input 
              name="first_name"
              placeholder="Jane" 
              value={formData.first_name}
              onChange={handleChange}
              className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600"
              required
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium text-neutral-300">Last Name</label>
            <Input 
              name="last_name"
              placeholder="Doe" 
              value={formData.last_name}
              onChange={handleChange}
              className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600"
              required
            />
          </div>
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium text-neutral-300">Work Email</label>
          <Input 
            type="email"
            name="email"
            placeholder="jane@acme.com" 
            value={formData.email}
            onChange={handleChange}
            className="bg-neutral-950 border-neutral-800 text-neutral-100 placeholder:text-neutral-600"
            required
          />
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium text-neutral-300">Password</label>
          <div className="relative">
            <Input 
              type={showPassword ? "text" : "password"} 
              name="password"
              placeholder="••••••••" 
              value={formData.password}
              onChange={handleChange}
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
          className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium mt-2"
        >
          {loading ? 'Creating account...' : 'Create Account'}
        </Button>
      </form>
      
      <div className="mt-6 text-center text-sm text-neutral-400">
        Already have an account?{' '}
        <Link href="/login" className="text-blue-500 hover:text-blue-400 font-medium">
          Sign In
        </Link>
      </div>
    </div>
  );
}
