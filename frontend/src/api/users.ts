import { apiClient } from "./client";
import type { User, UserCreate, UserUpdate } from "@/types";

export async function listUsers(): Promise<User[]> {
  const res = await apiClient.get<User[]>("/users/");
  return res.data;
}

export async function getUser(id: string): Promise<User> {
  const res = await apiClient.get<User>(`/users/${id}`);
  return res.data;
}

export async function createUser(data: UserCreate): Promise<User> {
  const res = await apiClient.post<User>("/users/", data);
  return res.data;
}

export async function updateUser(id: string, data: UserUpdate): Promise<User> {
  const res = await apiClient.put<User>(`/users/${id}`, data);
  return res.data;
}

export async function deleteUser(id: string): Promise<void> {
  await apiClient.delete(`/users/${id}`);
}

export async function changePassword(id: string, newPassword: string): Promise<void> {
  await apiClient.patch(`/users/${id}/password`, { new_password: newPassword });
}
