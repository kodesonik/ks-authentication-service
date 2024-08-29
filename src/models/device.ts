export interface IDevice {
  id: string;
  token: string;
  model?: string;
  brand?: string;
  platform: string;
  version?: string;
  isLoggedIn?: boolean;
  isActive: boolean;
  accountId: string;
}
