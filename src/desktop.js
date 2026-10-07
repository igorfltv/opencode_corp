import { execFile } from "node:child_process";
import { promisify } from "node:util";
const exec = promisify(execFile);

export async function openBrowser(url) {
  if (process.env.CORP_NO_BROWSER === "1") return;
  if (process.platform === "darwin") await exec("open", [url], { timeout: 5000 });
  else if (process.platform === "win32") await exec("rundll32.exe", ["url.dll,FileProtocolHandler", url], { timeout: 5000 });
  else await exec("xdg-open", [url], { timeout: 5000 });
}
export async function notifyDesktop(message) {
  if (process.env.CORP_NO_NOTIFICATIONS === "1") return;
  if (process.platform === "darwin") {
    await exec("osascript", ["-e", 'on run argv\n display notification (item 1 of argv) with title "Company OpenCode"\nend run', message], { timeout: 5000 });
  } else if (process.platform === "linux") await exec("notify-send", ["Company OpenCode", message], { timeout: 5000 });
}
