import { useState } from "react";
import { Copy, Check, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface PowerShellBlockProps {
  code: string;
  className?: string;
}

export function PowerShellBlock({ code, className }: PowerShellBlockProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className={cn("rounded-lg border border-yellow-300 bg-yellow-50 overflow-hidden", className)}>
      {/* Warning banner */}
      <div className="flex items-center gap-2 border-b border-yellow-300 bg-yellow-100 px-3 py-2 text-xs font-semibold text-yellow-800">
        <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
        Requires admin privileges — review carefully before applying
      </div>
      {/* Code area */}
      <div className="relative bg-gray-900 p-4">
        <Button
          size="sm"
          variant="ghost"
          onClick={handleCopy}
          className="absolute right-2 top-2 h-7 w-7 p-0 text-gray-400 hover:text-white"
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
        </Button>
        <pre className="overflow-x-auto pr-8 text-sm text-green-300 font-mono whitespace-pre-wrap break-words">
          {code}
        </pre>
      </div>
    </div>
  );
}
