import axios, { AxiosError, type AxiosInstance } from "axios";

import { API_BASE_URL } from "@/lib/constants";

const ACCESS_KEY = "sih1684_access_token";
const REFRESH_KEY = "sih1684_refresh_token";

export const tokenStorage = {
  getAccess(): string | null {
    return localStorage.getItem(ACCESS_KEY);
  },
  getRefresh(): string | null {
    return localStorage.getItem(REFRESH_KEY);
  },
  set(access: string, refresh: string) {
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
  },
  clear() {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
};

export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  headers: { "Content-Type": "application/json" },
  timeout: 30000,
});

// Inject the bearer token on every request.
apiClient.interceptors.request.use((config) => {
  const token = tokenStorage.getAccess();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let isRefreshing = false;

// Handle 401 (attempt a single refresh + retry) and 403 (redirect to login).
apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config as
      | (typeof error.config & { _retried?: boolean })
      | undefined;
    const status = error.response?.status;

    if (status === 401 && original && !original._retried && !isRefreshing) {
      const refresh = tokenStorage.getRefresh();
      if (refresh) {
        isRefreshing = true;
        try {
          const res = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: refresh,
          });
          const newToken = res.data.access_token as string;
          localStorage.setItem("sih1684_access_token", newToken);
          original._retried = true;
          original.headers = original.headers ?? {};
          (original.headers as Record<string, string>).Authorization =
            `Bearer ${newToken}`;
          return apiClient(original);
        } catch {
          tokenStorage.clear();
          if (window.location.pathname !== "/login") {
            window.location.href = "/login";
          }
        } finally {
          isRefreshing = false;
        }
      } else {
        tokenStorage.clear();
        if (window.location.pathname !== "/login") {
          window.location.href = "/login";
        }
      }
    }

    if (status === 403) {
      // Forbidden — keep the user logged in but surface the error to the caller.
      return Promise.reject(error);
    }

    return Promise.reject(error);
  }
);
