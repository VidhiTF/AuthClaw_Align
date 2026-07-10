import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { 
  LayoutDashboard, 
  Network, 
  ShieldCheck, 
  Activity, 
  Settings,
  Cloud,
  Wrench,
  FlaskConical
} from 'lucide-react';
import { useAuth } from '@/hooks/use-auth';

const NAV_ITEMS = [
  { name: 'Overview', href: '/overview', icon: LayoutDashboard },
  { name: 'Gateway', href: '/gateway', icon: Network },
  { name: 'Policies & Guardrails', href: '/policies', icon: ShieldCheck },
  { name: 'Agent & Remediation', href: '/agent-remediation', icon: Wrench, experimental: true },
  { name: 'Frameworks', href: '/frameworks', icon: ShieldCheck },
  { name: 'Audit & Trust Center', href: '/audit', icon: Activity },
  { name: 'Risk & Red Teaming', href: '/risk', icon: FlaskConical, experimental: true },
  { name: 'Integrations', href: '/integrations', icon: Cloud, experimental: true },
  { name: 'Settings', href: '/settings', icon: Settings },
];

const VISIBLE_NAV_ITEMS = NAV_ITEMS.filter(
  (item) => !item.experimental || process.env.NEXT_PUBLIC_ENABLE_EXPERIMENTAL_SURFACES === 'true',
);

export function Sidebar() {
  const pathname = usePathname();
  const { user } = useAuth();

  return (
    <>
    <div className="hidden md:flex w-64 border-r border-sidebar-border bg-sidebar flex-col h-screen fixed left-0 top-0">
      <div className="h-16 flex items-center px-6 border-b border-neutral-800">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center">
            <span className="text-white font-bold text-sm">AC</span>
          </div>
          <span className="font-bold text-lg text-white">AuthClaw</span>
        </div>
      </div>
      
      <div className="flex-1 py-6 flex flex-col gap-1 px-4">
        {VISIBLE_NAV_ITEMS.map((item) => {
          const isActive = pathname === item.href || (pathname?.startsWith(item.href) && item.href !== '/');
          
          return (
            <Link 
              key={item.href} 
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                isActive 
                  ? 'bg-blue-600/10 text-blue-500' 
                  : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900'
              }`}
            >
              <item.icon className="w-4 h-4" />
              {item.name}
            </Link>
          );
        })}
      </div>

      <div className="p-4 border-t border-neutral-800">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-neutral-800 flex items-center justify-center text-xs font-medium text-neutral-300 uppercase">
            {user?.first_name?.[0] || ''}{user?.last_name?.[0] || ''}
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-medium text-neutral-200">{user?.first_name} {user?.last_name}</span>
            <span className="text-xs text-neutral-500 truncate w-40">{user?.email}</span>
          </div>
        </div>
      </div>
    </div>
    <nav className="md:hidden fixed bottom-0 left-0 right-0 z-30 max-w-[100vw] border-t border-neutral-800 bg-sidebar/95 backdrop-blur overflow-hidden">
      <div className="flex max-w-full items-center gap-1 overflow-x-auto px-2 py-2">
        {VISIBLE_NAV_ITEMS.map((item) => {
          const isActive = pathname === item.href || (pathname?.startsWith(item.href) && item.href !== '/');
          return (
            <Link
              key={item.href}
              href={item.href}
              aria-label={item.name}
              className={`flex min-w-16 flex-col items-center gap-1 rounded-md px-2 py-1.5 text-[10px] font-medium transition-colors ${
                isActive
                  ? 'bg-blue-600/10 text-blue-400'
                  : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900'
              }`}
            >
              <item.icon className="w-4 h-4" />
              <span className="max-w-16 truncate">{item.name}</span>
            </Link>
          );
        })}
      </div>
    </nav>
    </>
  );
}
