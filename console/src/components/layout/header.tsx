import { usePathname } from 'next/navigation';
import { useAuth } from '@/hooks/use-auth';
import { Button } from '@/components/ui/button';
import { LogOut, Bell } from 'lucide-react';

export function Header() {
  const pathname = usePathname();
  const { logout, user } = useAuth();
  
  const segments = pathname?.split('/').filter(Boolean) || [];
  const titleMap: Record<string, string> = {
    '': 'Overview',
    gateway: 'Gateway',
    policies: 'Policies & Guardrails',
    'agent-remediation': 'Agent & Remediation',
    frameworks: 'Frameworks',
    audit: 'Audit & Trust Center',
    risk: 'Risk & Red Teaming',
    integrations: 'Integrations',
    settings: 'Settings',
  };
  const title = titleMap[segments[0] || ''] || segments[0].charAt(0).toUpperCase() + segments[0].slice(1);

  return (
    <header className="h-16 border-b border-neutral-800 bg-neutral-950 flex items-center justify-between gap-3 px-4 md:px-6 sticky top-0 z-10 w-full">
      <div className="flex min-w-0 items-center gap-2">
        <h1 className="truncate text-base md:text-lg font-semibold text-neutral-100">{title}</h1>
      </div>
      
      <div className="flex shrink-0 items-center gap-2 md:gap-4">
        <div className="hidden md:flex items-center gap-2 px-3 py-1 bg-neutral-900 border border-neutral-800 rounded-full text-xs text-neutral-400">
          <span className="w-2 h-2 rounded-full bg-green-500"></span>
          Tenant ID: {user?.tenant_id?.substring(0, 8)}...
        </div>
        
        <Button variant="ghost" size="icon" className="text-neutral-400">
          <Bell className="w-4 h-4" />
        </Button>
        
        <Button variant="ghost" size="sm" onClick={logout} className="text-neutral-400 hover:text-red-400">
          <LogOut className="w-4 h-4 mr-2" />
          <span className="hidden sm:inline">Logout</span>
        </Button>
      </div>
    </header>
  );
}
