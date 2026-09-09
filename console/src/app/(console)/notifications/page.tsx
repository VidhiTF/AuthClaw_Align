"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Bell, CheckCheck, CircleAlert, CircleCheck, TriangleAlert } from "lucide-react";
import { performNotificationMutation } from "@/lib/notification-mutation";
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

export default function NotificationsPage() {
  const [items, setItems] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [mutating, setMutating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch("/api/notifications?limit=100", { cache: "no-store" });
      if (!response.ok) return;
      const data = (await response.json()) as NotificationResponse;
      setItems(data.items || []);
      setUnreadCount(data.unread_count || 0);
    } catch {
      // Keep the page usable if the backend is temporarily unavailable.
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const markRead = async (id: string) => {
    setMutationError(null);
    setMutating(true);
    try {
      await performNotificationMutation(`/api/notifications/${id}/read`);
      await load();
    } catch {
      setMutationError("Could not mark the notification as read. Please try again.");
    } finally {
      setMutating(false);
    }
  };

  const markAllRead = async () => {
    setMutationError(null);
    setMutating(true);
    try {
      await performNotificationMutation("/api/notifications/read-all");
      await load();
    } catch {
      setMutationError("Could not mark notifications as read. Please try again.");
    } finally {
      setMutating(false);
    }
  };

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <div className="mb-3 flex h-11 w-11 items-center justify-center rounded-[14px] bg-[#F1ECFE] text-[#6D28D9]">
            <Bell className="h-5 w-5" />
          </div>
          <p className="text-xs font-bold uppercase tracking-wider text-[#6B7488]">Attention Center</p>
          <h1 className="mt-1 text-3xl font-black tracking-tight text-[#0E1726]">Notifications</h1>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-[#6B7488]">
            Approval, remediation, gateway, Trust Center, and compliance score events for this tenant.
          </p>
        </div>
        <button
          onClick={markAllRead}
          disabled={unreadCount === 0 || mutating}
          className="inline-flex items-center justify-center gap-2 rounded-lg border border-[#E6E9F0] bg-white px-4 py-2.5 text-xs font-bold text-[#475069] shadow-sm hover:bg-[#F5F7FA] disabled:text-[#A8B0C0]"
        >
          <CheckCheck className="h-4 w-4" />
          Mark all read
        </button>
      </div>

      {mutationError && (
        <div role="alert" className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700">
          {mutationError}
        </div>
      )}

      <div className="rounded-[20px] border border-[#E6E9F0] bg-white shadow-[0_1px_2px_rgba(11,31,63,.05),0_12px_30px_-12px_rgba(11,31,63,.18)]">
        <div className="flex items-center justify-between border-b border-[#E6E9F0] px-5 py-4">
          <p className="text-sm font-bold text-[#0E1726]">Latest events</p>
          <span className="rounded-full bg-[#F5F7FA] px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider text-[#6B7488]">
            {unreadCount} unread
          </span>
        </div>

        <div className="divide-y divide-[#E6E9F0]">
          {loading ? (
            <div className="p-8 text-sm text-[#6B7488]">Loading notifications...</div>
          ) : items.length === 0 ? (
            <div className="p-8 text-sm text-[#6B7488]">No notifications yet.</div>
          ) : (
            items.map((item) => {
              const Icon = severityIcon[item.severity] || CircleCheck;
              return (
                <div key={item.id} className={`p-5 ${item.read_at ? "bg-white" : "bg-[#FBFAF9]"}`}>
                  <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                    <div className="flex min-w-0 gap-3">
                      <div className={`mt-0.5 flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg border ${severityClass[item.severity]}`}>
                        <Icon className="h-4 w-4" />
                      </div>
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <h2 className="text-sm font-bold text-[#0E1726]">{item.title}</h2>
                          {!item.read_at && <span className="rounded-full bg-[#6D28D9] px-2 py-0.5 text-[9px] font-bold uppercase text-white">Unread</span>}
                        </div>
                        <p className="mt-1 text-sm leading-relaxed text-[#475069]">{item.body || item.type.replaceAll("_", " ")}</p>
                        <p className="mt-2 text-[11px] font-medium text-[#6B7488]">{formatDateTime(item.created_at)}</p>
                      </div>
                    </div>
                    <div className="flex flex-shrink-0 flex-wrap gap-2">
                      {!item.read_at && (
                        <button
                          onClick={() => void markRead(item.id)}
                          disabled={mutating}
                          className="rounded-lg border border-[#E6E9F0] px-3 py-2 text-[10px] font-bold text-[#475069] hover:bg-[#F5F7FA]"
                        >
                          Mark read
                        </button>
                      )}
                      {item.link && (
                        <Link
                          href={item.link}
                          onClick={() => void markRead(item.id)}
                          className="rounded-lg bg-[#6D28D9] px-3 py-2 text-[10px] font-bold text-white hover:bg-[#5B21B6]"
                        >
                          Open
                        </Link>
                      )}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
