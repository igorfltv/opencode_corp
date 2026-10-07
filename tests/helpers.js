export async function approveBrowser(url, account = "engineer", jsonResponse = false) {
  const response = await fetch(url);
  const page = await response.text();
  const requestID = page.match(/name="requestID" value="([^"]+)"/)?.[1];
  const csrf = page.match(/name="csrf" value="([^"]+)"/)?.[1];
  if (!requestID || !csrf) throw new Error("Login page does not contain its form");
  const approved = await fetch(`${new URL(url).origin}/oauth/approve`, { method: "POST", redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: new URL(url).origin, Accept: jsonResponse ? "application/json" : "text/html" },
    body: new URLSearchParams({ requestID, csrf, account }),
  });
  if (jsonResponse) {
    if (!approved.ok) throw new Error(`Approval failed ${approved.status}`);
    return (await approved.json()).redirect;
  }
  if (approved.status !== 303) throw new Error(`Approval failed ${approved.status}`);
  return approved.headers.get("location");
}
