import { AlertTriangle, FileQuestion, RefreshCw } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

export function EmptyState({ 
  title = "No data found", 
  description = "There are no records to display at this time.",
  icon: Icon = FileQuestion,
  action
}: { 
  title?: string;
  description?: string;
  icon?: LucideIcon;
  action?: { label: string; onClick: () => void }
}) {
  return (
    <Card className="bg-neutral-900/50 border-neutral-800/50 border-dashed">
      <CardContent className="flex flex-col items-center justify-center py-16 px-4 text-center">
        <div className="w-12 h-12 rounded-full bg-neutral-800/50 flex items-center justify-center mb-4">
          <Icon className="w-6 h-6 text-neutral-400" />
        </div>
        <h3 className="text-lg font-medium text-neutral-200 mb-1">{title}</h3>
        <p className="text-sm text-neutral-500 max-w-sm mb-6">{description}</p>
        {action && (
          <Button variant="outline" onClick={action.onClick} className="border-neutral-700 hover:bg-neutral-800">
            {action.label}
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

export function ErrorState({ 
  title = "Something went wrong", 
  description = "Failed to load data. Please try again later.",
  error,
  onRetry
}: { 
  title?: string;
  description?: string;
  error?: unknown;
  onRetry?: () => void 
}) {
  const errorMessage =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : String(error);

  return (
    <Card className="bg-red-950/10 border-red-900/20">
      <CardContent className="flex flex-col items-center justify-center py-16 px-4 text-center">
        <div className="w-12 h-12 rounded-full bg-red-900/20 flex items-center justify-center mb-4">
          <AlertTriangle className="w-6 h-6 text-red-500" />
        </div>
        <h3 className="text-lg font-medium text-red-200 mb-1">{title}</h3>
        <p className="text-sm text-red-400/70 max-w-sm mb-2">{description}</p>
        {error != null && (
          <p className="text-xs font-mono text-red-500/50 bg-red-950/30 px-2 py-1 rounded max-w-md overflow-hidden text-ellipsis mb-6">
            {errorMessage}
          </p>
        )}
        {onRetry && (
          <Button variant="outline" onClick={onRetry} className="border-red-900/30 hover:bg-red-900/20 text-red-400">
            <RefreshCw className="w-4 h-4 mr-2" />
            Try Again
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
