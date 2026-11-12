import { withoutHidden } from "./visibleName";

// Text that asks for a secret: a password, passphrase, PIN, one-time or
// verification code. Common languages. Used to mask keyboard-interactive
// answers even when the server asked for echo (F-079), and to recognise a
// terminal waiting for a secret (F-023, F-084, F-085).
export const SECRET_PROMPT = /pass(word|phrase|code|wort)?|mot de passe|contrase|senha|wachtwoord|l\u00f6senord|adgangskode|has\u0142o|parol|heslo|salasana|jelsz|\u043f\u0430\u0440\u043e\u043b\u044c|\u5bc6\u7801|\u5bc6\u78bc|\u30d1\u30b9\u30ef\u30fc\u30c9|\ube44\ubc00\ubc88\ud638|\bpin\b|\botp\b|\bcode\b|token|secret/i;

// Does a terminal's output end with a prompt for a secret? The last line,
// colour and other escape sequences and hidden characters removed, must name a
// secret and end with a colon followed only by spaces or the asterisks some
// prompts echo per key (sudo's pwfeedback). Used to keep what is typed there
// out of command history, snippet expansion and broadcast. A heuristic: the
// history check also asks that the typed text was echoed on screen.
export const looksLikeSecretPrompt = (output: string): boolean => {
  const clean = output
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "") // OSC ... BEL/ST
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")         // CSI ... final
    .replace(/[\x08\x7f]/g, "");                        // a deleted asterisk's echo
  const lastLine = withoutHidden(clean.slice(clean.search(/[^\r\n]*$/)).slice(-160));
  const end = lastLine.search(/[:\uff1a][\s*]*$/);
  return end > 0 && SECRET_PROMPT.test(lastLine.slice(0, end));
};
