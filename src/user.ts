import { Authenticator, AuthenticatorCheckCredentialsResponse, stripUsernamePasswordFromHeader } from "./auth";
import { errorString } from "./utils";

export const SHA256_PREFIX = "sha256";
export const SHA256_PREFIX_LEN = SHA256_PREFIX.length + 1; // add ":"

export function hexToDigest(sha256: ArrayBuffer, prefix: string = SHA256_PREFIX + ":") {
  const digest = [...new Uint8Array(sha256)].map((b) => b.toString(16).padStart(2, "0")).join("");

  return `${prefix}${digest}`;
}

function stringToArrayBuffer(s: string): Uint8Array {
  const encoder = new TextEncoder();
  const arr = encoder.encode(s);
  return arr;
}

export async function getSHA256(data: string, prefix: string = SHA256_PREFIX + ":"): Promise<string> {
  const sha256 = new crypto.DigestStream("SHA-256");
  const w = sha256.getWriter();
  const encoder = new TextEncoder();
  const arr = encoder.encode(data);
  w.write(arr);
  w.close();
  return hexToDigest(await sha256.digest, prefix);
}

export type AuthenticatorCredentials = {
  username: string;
  password: string;
};

export class UserAuthenticator implements Authenticator {
  authmode: string;
  constructor(private admin?: AuthenticatorCredentials) {
    this.authmode = "UserAuthenticator";
  }

  async checkCredentials(r: Request): Promise<AuthenticatorCheckCredentialsResponse> {
    const res = stripUsernamePasswordFromHeader(r);

    // Default to pull access for everyone (anonymous or invalid credentials)
    const pullOnlyResponse: AuthenticatorCheckCredentialsResponse = {
      verified: true,
      payload: {
        username: "anonymous",
        capabilities: ["pull"],
        exp: Date.now() + 60 * 60,
        aud: "",
      },
    };

    if (!this.admin) {
      // No admin configured -> Read-only for everyone
      return pullOnlyResponse;
    }

    if ("verified" in res) {
      // No credentials or invalid header format -> Pull access
      return pullOnlyResponse;
    }

    const [username, password] = res;

    try {
      // Check if it matches the admin credentials
      const usernameMatch = crypto.subtle.timingSafeEqual(
        stringToArrayBuffer(username),
        stringToArrayBuffer(this.admin.username)
      );

      const passwordMatch = crypto.subtle.timingSafeEqual(
        stringToArrayBuffer(password),
        stringToArrayBuffer(this.admin.password)
      );

      if (usernameMatch && passwordMatch) {
        // Admin -> Push + Pull access
        return {
          verified: true,
          payload: {
            username: this.admin.username,
            capabilities: ["pull", "push"],
            exp: Date.now() + 60 * 60,
            aud: "",
          },
        };
      }
    } catch (err) {
      console.error(`Failed authentication timingSafeEqual: ${errorString(err)}`);
      // On error, fall back to pull access
      return pullOnlyResponse;
    }

    // Credentials provided but incorrect -> Pull access
    return pullOnlyResponse;
  }
}
