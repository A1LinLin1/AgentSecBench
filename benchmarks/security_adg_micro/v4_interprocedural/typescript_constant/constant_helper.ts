import { exec } from "node:child_process";

export function executeConstant(value: string) {
  return exec(value);
}
