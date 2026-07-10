import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function TableSkeleton({ 
  columns = 5, 
  rows = 5 
}: { 
  columns?: number;
  rows?: number;
}) {
  return (
    <div className="rounded-md border border-neutral-800 bg-neutral-900/30 overflow-hidden">
      <Table>
        <TableHeader className="bg-neutral-800/50">
          <TableRow className="border-neutral-800 hover:bg-transparent">
            {Array.from({ length: columns }).map((_, i) => (
              <TableHead key={`h-${i}`}>
                <Skeleton className="h-4 w-24 bg-neutral-800" />
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {Array.from({ length: rows }).map((_, r) => (
            <TableRow key={`r-${r}`} className="border-neutral-800 hover:bg-transparent">
              {Array.from({ length: columns }).map((_, c) => (
                <TableCell key={`c-${r}-${c}`} className="py-4">
                  <Skeleton className={`h-4 bg-neutral-800/80 ${c === 0 ? 'w-32' : c === columns - 1 ? 'w-16' : 'w-full'}`} />
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

export function CardSkeleton() {
  return (
    <div className="rounded-xl border border-neutral-800 bg-neutral-900/30 p-6 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <Skeleton className="h-5 w-32 bg-neutral-800" />
        <Skeleton className="h-8 w-8 rounded-full bg-neutral-800" />
      </div>
      <Skeleton className="h-10 w-24 bg-neutral-800" />
      <Skeleton className="h-4 w-48 bg-neutral-800/50" />
    </div>
  );
}
