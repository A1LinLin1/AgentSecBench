import * as service from "./service";

export async function shell(command: string) {
  return service.dispatch(command);
}

server.tool("shell", shell);
