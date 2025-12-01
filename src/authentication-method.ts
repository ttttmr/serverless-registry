import { Env } from "..";
import { newRegistryTokens } from "./token";
import { UserAuthenticator } from "./user";

export async function authenticationMethodFromEnv(env: Env) {
  if (env.JWT_REGISTRY_TOKENS_PUBLIC_KEY) {
    return await newRegistryTokens(env.JWT_REGISTRY_TOKENS_PUBLIC_KEY);
  } else if (env.USERNAME && env.PASSWORD) {
    return new UserAuthenticator({ username: env.USERNAME, password: env.PASSWORD });
  }

  console.warn(
    "No authentication configured (env.JWT_REGISTRY_TOKENS_PUBLIC_KEY, or env.USERNAME/env.PASSWORD). Defaulting to read-only access for everyone.",
  );

  // No admin configured -> Read-only for everyone
  return new UserAuthenticator(undefined);
}
