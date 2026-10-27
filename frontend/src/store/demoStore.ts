import { create } from "zustand";

interface DemoState {
  isDemoMode: boolean;
  toggle: () => void;
  set: (value: boolean) => void;
}

const envDemo = (import.meta.env.VITE_DEMO_MODE ?? "").toLowerCase();
const initialDemo =
  envDemo === "true" || envDemo === "1" || envDemo === "yes";

export const useDemoStore = create<DemoState>((set) => ({
  isDemoMode: initialDemo,
  toggle: () => set((s) => ({ isDemoMode: !s.isDemoMode })),
  set: (value: boolean) => set({ isDemoMode: value }),
}));
