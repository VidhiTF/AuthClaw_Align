"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Bell, CheckCheck, CircleAlert, CircleCheck, TriangleAlert } from "lucide-react";
import { formatDateTime } from "@/lib/ui-format";

type Notification = {
  id: string;
  type: string;
  severity: "info" | "warning" | "critical";
  title: string;
  body: string;
  link: string | null;
  read_at: string | null;
  created_at: string;
};

type NotificationResponse = {
  items: Notification[];
  unread_count: number;
};

const severityClass = {
  info: "border-sky-200 bg-sky-50 text-sky-700",
  warning: "border-amber-200 bg-amber-50 text-amber-700",
  critical: "border-red-200 bg-red-50 text-red-700",
};

const severityIcon = {
  info: CircleCheck,
  warning: TriangleAlert,
  critical: CircleAlert,
};

export default function NotificationBell() {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);

  const load = useCallback(async () => {
    try {
      const response = await fetch("/api/notifications?limit=10", { cache: "no-store" });
      if (!response.ok) return;
      const data = (await response.json()) as NotificationResponse;
      setItems(data.items || []);
      setUnreadCount(data.unread_count || 0);
    } catch {
      // Header polling should never break the console shell.
    }
  }, []);

  useEffect(() => {
    const initial = window.setTimeout(() => void load(), 0);
    const timer = window.setInterval(() => void load(), 45_000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, [load]);

  const markRead = async (id: string) => {
    const wasUnread = items.some((item) => item.id === id && !item.read_at);
    setItems((current) => current.map((item) => item.id === id ? { ...item, read_at: new Date().toISOString() } : item));
    if (wasUnread) setUnreadCount((current) => Math.max(0, current - 1));
    await fetch(`/api/notifications/${id}/read`, { method: "POST" }).catch(() => undefined);
  };

  const markAllRead = async () => {
    setItems((current) => current.map((item) => ({ ...item, read_at: item.read_at || new Date().toISOString() })));
    setUnreadCount(0);
    await fetch("/api/notifications/read-all", { method: "POST" }).catch(() => undefined);
  };

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((current) => !current)}
        className="relative inline-flex h-9 w-9 items-center justify-center rounded-[10px] border border-[#E6E9F0] bg-white text-[#475069] transition hover:border-[#A78BFA] hover:bg-[#F5F7FA] hover:text-[#0E1726]"
        aria-label="Notifications"
      >
        <Bell className="h-4.5 w-4.5" />
        {unreadCount > 0 && (
          <span className="absolute -right-1 -top-1 min-w-5 rounded-full bg-red-500 px-1.5 py-0.5 text-[10px] font-bold leading-none text-white">
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </button>

      <div
        className={`fixed inset-0 z-30 ${open ? "pointer-events-auto" : "pointer-events-none"}`}
        onClick={() => setOpen(false)}
      />
      <div
        className={`absolute right-0 z-40 mt-2 w-[min(22rem,calc(100vw-2rem))] origin-top-right rounded-[14px] border border-[#E6E9F0] bg-white shadow-[0_1px_2px_rgba(11,31,63,.05),0_20px_48px_-20px_rgba(11,31,63,.28)] transition-all duration-150 ${
          open ? "pointer-events-auto translate-y-0 scale-100 opacity-100" : "pointer-events-none -translate-y-1 scale-95 opacity-0"
        }`}
      >
        <div className="flex items-center justify-between border-b border-[#E6E9F0] px-4 py-3">
          <div>
            <p className="text-sm font-bold text-[#0E1726]">Notifications</p>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-[#6B7488]">{unreadCount} unread</p>
          </div>
          <button
            onClick={markAllRead}
            disabled={unreadCount === 0}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[#E6E9F0] px-2.5 py-1.5 text-[10px] font-bold text-[#475069] hover:bg-[#F5F7FA] disabled:text-[#A8B0C0]"
          >
            <CheckCheck className="h-3.5 w-3.5" />
            Read all
          </button>
        </div>

        <div className="max-h-96 overflow-y-auto p-2">
          {items.length === 0 ? (
            <div className="rounded-lg border border-[#E6E9F0] bg-[#F5F7FA] p-4 text-xs text-[#6B7488]">No notifications yet.</div>
          ) : (
            items.map((item) => {
              const Icon = severityIcon[item.severity] || CircleCheck;
              const content = (
                <div className={`rounded-lg border p-3 ${item.read_at ? "border-[#E6E9F0] bg-white" : severityClass[item.severity]}`}>
                  <div className="flex items-start gap-2">
                    <Icon className="mt-0.5 h-4 w-4 flex-shrink-0" />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-start justify-between gap-2">
                        <p className="text-xs font-bold">{item.title}</p>
                        {!item.read_at && <span className="mt-1 h-2 w-2 flex-shrink-0 rounded-full bg-current" />}
                      </div>
                      {item.body && <p className="mt-1 text-xs leading-relaxed text-[#475069]">{item.body}</p>}
                      <p className="mt-2 text-[10px] font-medium text-[#6B7488]">{formatDateTime(item.created_at)}</p>
                    </div>
                  </div>
                </div>
              );
              return item.link ? (
                <Link
                  key={item.id}
                  href={item.link}
                  onClick={() => {
                    void markRead(item.id);
                    setOpen(false);
                  }}
                  className="mb-2 block"
                >
                  {content}
                </Link>
              ) : (
                <button key={item.id} onClick={() => void markRead(item.id)} className="mb-2 block w-full text-left">
                  {content}
                </button>
              );
            })
          )}
        </div>

        <div className="border-t border-[#E6E9F0] p-2">
          <Link
            href="/notifications"
            onClick={() => setOpen(false)}
            className="block rounded-lg px-3 py-2 text-center text-xs font-bold text-[#6D28D9] hover:bg-[#F5F7FA]"
          >
            View all notifications
          </Link>
        </div>
      </div>
    </div>
  );
}
