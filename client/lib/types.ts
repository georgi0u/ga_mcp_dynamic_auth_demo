export type User = {
  id: string;
  email: string;
  created_at: string;
};

export type Conversation = {
  id: string;
  user_id: string;
  title: string;
  last_openai_response_id?: string;
  created_at: string;
  updated_at: string;
};

export type Message = {
  id: string;
  conversation_id: string;
  role: "user" | "assistant";
  content: string;
  created_at: string;
};

export type Connection = {
  id: string;
  user_id: string;
  name: string;
  endpoint: string;
  canonical_resource: string;
  status: string;
  scopes: string[];
  auth_required: boolean;
  last_error?: string;
  last_verified_at?: string;
};

export type BootstrapResponse = {
  user: User;
  token: string;
  conversation: Conversation;
  messages: Message[];
  connections: Connection[];
};

export type LoginResponse = {
  token: string;
  expires_at: string;
  user: User;
};

export type BeginConnectResponse = {
  connection: Connection;
  authorization_url?: string;
};

export type ConnectionToolDefinition = {
  function_name: string;
  connection_id: string;
  connection_name: string;
  mcp_name: string;
  description: string;
  parameters: Record<string, unknown>;
};

export type ConnectionToolsResponse = {
  connection: Connection;
  tools: ConnectionToolDefinition[];
};

export type WebsocketPayload =
  | { type: "chat.message"; message: Message }
  | { type: "chat.status"; status: "idle" | "working" }
  | { type: "chat.error"; error: string };
