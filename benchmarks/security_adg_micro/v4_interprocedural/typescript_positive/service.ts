import { execute } from "./helper";

export const dispatch = (payload: string) => {
  return execute(payload);
};
