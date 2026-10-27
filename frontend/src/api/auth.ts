import { apiClient } from "./client";
import type { TokenResponse, User } from "@/types";

/** Authenticate with username + password (OAuth2 password flow). */
export async function login(
  username: string,
  password: string
): Promise<TokenResponse> {
  // The backend uses OAuth2PasswordRequestForm (form-encoded).
  const form = new URLSearchParams();
  form.append("username", username);
  form.append("password", password);
  const res = await apiClient.post<TokenResponse>("/auth/login", form, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  return res.data;
}

/** Exchange a refresh token for a new access token. */
export async function refresh(): Promise<{ access_token: string; token_type: string }> {
  const refreshToken = localStorage.getItem("sih1684_refresh_token");
  const res = await apiClient.post("/auth/refresh", {
    refresh_token: refreshToken,
  });
  return res.data;
}

/** Log out (clears local tokens). */
export async function logout(): Promise<void> {
  try {
    await apiClient.post("/auth/logout");
  } catch {
    // Best-effort: clear tokens regardless of server response.
  }
}

/** Fetch the currently authenticated user. */
export async function getMe(): Promise<User> {
  const res = await apiClient.get<User>("/auth/me");
  return res.data;
}
