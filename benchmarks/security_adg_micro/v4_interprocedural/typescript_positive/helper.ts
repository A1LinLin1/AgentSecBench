import { exec } from "node:child_process";

export function execute(value: string) {
  return exec(value);
}
