import * as React from "react";

import type { Severity } from "@/types";

export type ToastVariant = "default" | "destructive" | NonNullable<Severity>;

export interface Toast {
  id: string;
  title?: string;
  description?: string;
  variant?: ToastVariant;
  duration?: number;
}

interface State {
  toasts: Toast[];
}

type Action =
  | { type: "ADD"; toast: Toast }
  | { type: "DISMISS"; id: string };

let count = 0;
function genId(): string {
  count = (count + 1) % Number.MAX_SAFE_INTEGER;
  return count.toString();
}

const listeners: Array<(state: State) => void> = [];
let memoryState: State = { toasts: [] };

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "ADD":
      return { toasts: [...state.toasts, action.toast] };
    case "DISMISS":
      return {
        toasts: state.toasts.filter((t) => t.id !== action.id),
      };
  }
}

function dispatch(action: Action) {
  memoryState = reducer(memoryState, action);
  listeners.forEach((l) => l(memoryState));
}

/** Programmatically show a toast. */
export function toast(toast: Omit<Toast, "id">) {
  const id = genId();
  const duration = toast.duration ?? 5000;
  dispatch({ type: "ADD", toast: { ...toast, id } });
  if (duration > 0) {
    setTimeout(() => dispatch({ type: "DISMISS", id }), duration);
  }
  return id;
}

/** Subscribe to toast state changes. */
export function useToast(): State {
  const [state, setState] = React.useState<State>(memoryState);
  React.useEffect(() => {
    listeners.push(setState);
    return () => {
      const idx = listeners.indexOf(setState);
      if (idx > -1) listeners.splice(idx, 1);
    };
  }, []);
  return state;
}

export function dismissToast(id: string) {
  dispatch({ type: "DISMISS", id });
}
