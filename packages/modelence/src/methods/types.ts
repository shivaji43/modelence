import { Session, UserInfo, Permission } from '../auth/types';

export type ClientInfo = {
  screenWidth: number;
  screenHeight: number;
  windowWidth: number;
  windowHeight: number;
  pixelRatio: number;
  orientation: string | null;
};

export type ConnectionInfo = {
  ip?: string;
  userAgent?: string;
  acceptLanguage?: string;
  referrer?: string;
  baseUrl?: string;
};

export type Context = {
  session: Session | null;
  user: UserInfo | null;
  roles: string[];
  clientInfo: ClientInfo;
  connectionInfo: ConnectionInfo;
};

export type Args = Record<string, unknown>;

export type Handler<T extends any> = (args: Args, context: Context) => Promise<T> | T;

export type MethodType = 'query' | 'mutation';

export type MethodDefinition<T extends any> = {
  permissions?: Permission[];
  handler: Handler<T>;
} | Handler<T>;

export type Method<T extends any[]> = {
  type: MethodType;
  name: string;
  permissions: Permission[];
  handler: Handler<T>;
};
