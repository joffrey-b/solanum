import test from "node:test";
import assert from "node:assert/strict";
import { looksLikeSecretPrompt } from "./secretPrompt.mjs";

export const SECRET = [
  "Password: ",
  "\r\n[sudo] password for joe: ",
  "[sudo] password for joe: ****",
  "[sudo] password for joe: **\b \b",
  "Passwort: ",
  "Mot de passe : ",
  "Contrase\u00f1a: ",
  "\u5bc6\u7801\uff1a",
  "\u30d1\u30b9\u30ef\u30fc\u30c9:",
  "Enter passphrase for key '/home/u/.ssh/id_ed25519': ",
  "Verification code: ",
  "Enter PIN for 'token': ",
  "\x1b[1mPassword:\x1b[0m ",
  "Pass\u200bword: ",
];
export const NOT_SECRET = [
  "user@token-host:~$ ",
  "Password changed.\r\n$ ",
  "",
  "ls -la\r\n",
  "error: no such file",
  "Password: hunter22",
];

{
  const check = looksLikeSecretPrompt;
  test("secret prompts: recognised", () => {
    const missed = SECRET.filter((p) => !check(p));
    assert.deepEqual(missed, []);
  });
  test("secret prompts: other output is not a prompt", () => {
    const wrong = NOT_SECRET.filter((p) => check(p));
    assert.deepEqual(wrong, []);
  });
}
