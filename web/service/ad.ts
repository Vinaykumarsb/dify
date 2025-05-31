import { get, post, put } from './base' // Assuming these are the utility functions

// Matches ADConfigurationSchema from backend, excluding fields not sent/received or handled differently.
export interface ADConfig {
  id?: string; // Optional: only present for existing configs
  tenant_id?: string; // Usually handled by backend based on authenticated user/admin context
  is_enabled: boolean;
  server_url: string;
  bind_dn?: string | null; // Optional fields can be null from backend if cleared
  bind_password?: string; // Write-only, sent for PUT/POST, not expected in GET response
  user_search_base: string;
  user_search_filter?: string | null;
  group_search_base?: string | null;
  group_search_filter?: string | null;
  attribute_mapping_username?: string | null;
  attribute_mapping_email?: string | null;
  attribute_mapping_display_name?: string | null;
  created_at?: string; // Read-only
  updated_at?: string; // Read-only
}

// For GET response, password will not be included
export interface ADConfigResponse extends Omit<ADConfig, 'bind_password'> {}

// For test connection, we send a subset of fields, including potentially a password
export interface ADTestConnectionPayload {
  server_url: string;
  bind_dn?: string | null;
  bind_password?: string;
  // Other fields from ADConfig are not strictly needed for test_connection endpoint,
  // but the backend ADConfigurationTestRequestSchema expects them (server_url, bind_dn, bind_password).
  // Let's align with what the backend test endpoint expects.
}


export const fetchADConfig = () => {
  return get<ADConfigResponse>('/admin/ad/configuration')
}

export const updateADConfig = (data: Partial<ADConfig>) => {
  // The data type here is Partial<ADConfig> because user might only send updated fields.
  // Backend ADConfigurationSchema will validate.
  return put<ADConfig, ADConfigResponse>('/admin/ad/configuration', { body: data })
}

export const testADConnection = (data: ADTestConnectionPayload) => {
  return post<{ status: string; error?: string }, ADTestConnectionPayload>('/admin/ad/test-connection', { body: data })
}
