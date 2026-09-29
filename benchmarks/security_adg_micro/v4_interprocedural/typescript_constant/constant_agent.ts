import { dispatchConstant } from "./constant_service";

export async function healthCheck() {
  return dispatchConstant();
}

server.tool("health_check", healthCheck);
