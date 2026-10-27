import { useCallback } from "react";

import { login as apiLogin, getMe } from "@/api/auth";
import { useAuthStore } from "@/store/authStore";
import { tokenStorage } from "@/api/client";
import type { User } from "@/types";

/**
 * Wraps the auth store, exposing a `signIn()` that calls the API and stores
 * the returned tokens + user. Authentication is never simulated locally.
 */
export function useAuth() {
  const { user, isAuthenticated, login, logout, setUser } = useAuthStore();

  const signIn = useCallback(
    async (username: string, password: string): Promise<User> => {
      const res = await apiLogin(username, password);
      tokenStorage.set(res.access_token, res.refresh_token);
      login(res.user, res.access_token, res.refresh_token);
      return res.user;
    },
    [login]
  );

  const signOut = useCallback(async () => {
    tokenStorage.clear();
    logout();
  }, [logout]);

  const refreshUser = useCallback(async () => {
    const me = await getMe();
    setUser(me);
    return me;
  }, [setUser]);

  return { user, isAuthenticated, signIn, signOut, refreshUser, setUser };
}
