"use client";

import { ChevronDown } from "lucide-react";
import { formatLabel } from "@/lib/ui-format";

type FilterSelectProps = {
  label: string;
  value: string;
  options: readonly string[];
  onChange: (value: string) => void;
};

export default function FilterSelect({ label, value, options, onChange }: FilterSelectProps) {
  return (
    <div className="relative">
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="appearance-none bg-white border border-[#E6E9F0] text-[#475069] text-xs rounded-lg px-3 py-2 pr-8 focus:outline-none focus:ring-1 focus:ring-indigo-500/50 focus:border-indigo-500/50 cursor-pointer hover:border-[#A78BFA] transition-colors"
      >
        <option value="">{label}</option>
        {options.slice(1).map((option) => (
          <option key={option} value={option}>
            {formatLabel(option)}
          </option>
        ))}
      </select>
      <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-[#6B7488] pointer-events-none" />
    </div>
  );
}
