import type { IncomingMessage, ServerResponse } from "node:http";

/**
 * Public pages: landing page, legal notice and privacy policy.
 * Facts about the publisher are read from the environment; while they are missing, a visible
 * placeholder is shown ("[À COMPLÉTER : ...]"). Never invent them.
 */

const esc = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function fact(env: NodeJS.ProcessEnv, key: string, label: string): string {
  const v = (env[key] ?? "").trim();
  return v ? esc(v) : `<mark>[À COMPLÉTER : ${esc(label)} — variable ${key}]</mark>`;
}

export const LEGAL_PATH = "/mentions-legales";
export const PRIVACY_PATH = "/confidentialite";

const CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} – mmcp.sxncorp.fr</title>
<meta name="description" content="${esc(title)} du service mailmcp (mmcp.sxncorp.fr).">
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#222}footer{margin-top:3rem;padding-top:1rem;border-top:1px solid #ccc;font-size:.9rem}footer a{margin-right:1rem}mark{background:#fff3b0}</style>
</head>
<body>
<main>
${body}
</main>
<footer>
<nav aria-label="Liens légaux"><a href="/">Accueil</a><a href="${LEGAL_PATH}">Mentions légales</a><a href="${PRIVACY_PATH}">Politique de confidentialité</a></nav>
</footer>
</body>
</html>
`;
}

function home(): string {
  return layout(
    "mailmcp",
    `<h1>mailmcp</h1>
<p>Serveur MCP (Model Context Protocol) reliant une messagerie auto-hébergée (IMAP/SMTP) à un assistant IA. Ce service est privé : l'accès au point d'entrée <code>/mcp</code> est réservé aux personnes disposant d'un jeton d'authentification, et l'interface d'administration n'est pas accessible publiquement par défaut.</p>`,
  );
}

function legalNotice(env: NodeJS.ProcessEnv): string {
  return layout(
    "Mentions légales",
    `<h1>Mentions légales</h1>
<h2>Éditeur du site</h2>
<p>Site : mmcp.sxncorp.fr<br>
Éditeur : ${fact(env, "LEGAL_PUBLISHER_NAME", "nom ou raison sociale de l'éditeur")}<br>
Adresse : ${fact(env, "LEGAL_PUBLISHER_ADDRESS", "adresse postale de l'éditeur")}<br>
Contact : ${fact(env, "LEGAL_CONTACT_EMAIL", "adresse e-mail de contact")}<br>
Directeur de la publication : ${fact(env, "LEGAL_PUBLICATION_DIRECTOR", "nom du directeur de la publication")}</p>
<h2>Hébergeur</h2>
<p>${fact(env, "LEGAL_HOST", "nom, adresse et contact de l'hébergeur")}</p>
<h2>Propriété intellectuelle</h2>
<p>Le logiciel mailmcp est distribué sous licence MIT.</p>
<h2>Données personnelles</h2>
<p>Voir la <a href="${PRIVACY_PATH}">politique de confidentialité</a>.</p>`,
  );
}

function privacy(env: NodeJS.ProcessEnv): string {
  return layout(
    "Politique de confidentialité",
    `<h1>Politique de confidentialité</h1>
<h2>Responsable du traitement</h2>
<p>${fact(env, "LEGAL_PUBLISHER_NAME", "nom de l'éditeur / responsable du traitement")} — contact : ${fact(env, "LEGAL_CONTACT_EMAIL", "adresse e-mail de contact")}</p>
<h2>Données traitées</h2>
<ul>
<li><strong>Visiteurs du site public</strong> : les pages publiques (accueil, mentions légales, confidentialité) ne contiennent ni formulaire, ni traceur, ni cookie, ni outil de mesure d'audience. Comme tout serveur web, le serveur et son proxy peuvent enregistrer dans leurs journaux techniques l'adresse IP, la date, l'URL demandée et le navigateur, à des fins de sécurité et de bon fonctionnement (intérêt légitime, art. 6.1.f RGPD). Durée de conservation : ${fact(env, "LEGAL_LOG_RETENTION", "durée de conservation des journaux")}.</li>
<li><strong>Utilisateur autorisé du service</strong> : l'accès à <code>/mcp</code> et à l'administration est protégé par un jeton. L'administration utilise un unique cookie de session technique (<code>mailmcp_admin</code>, HttpOnly, durée 1 heure) strictement nécessaire à l'authentification, qui ne requiert pas de consentement.</li>
<li><strong>Messagerie connectée</strong> : à la demande de l'utilisateur autorisé, le service lit et envoie des courriels via les boîtes configurées. Les identifiants des boîtes ajoutées via l'administration sont stockés chiffrés (AES-256-GCM) sur le serveur. Le contenu des messages n'est pas conservé par le service ; il est transmis à l'assistant IA utilisé par l'utilisateur autorisé, sous sa responsabilité.</li>
</ul>
<h2>Destinataires</h2>
<p>Les données ne sont ni vendues ni cédées. Elles sont accessibles à l'éditeur et à l'hébergeur (${fact(env, "LEGAL_HOST", "hébergeur")}) en tant que sous-traitant technique.</p>
<h2>Vos droits</h2>
<p>Conformément au RGPD, vous disposez des droits d'accès, de rectification, d'effacement, de limitation, d'opposition et de portabilité. Pour les exercer, écrivez à ${fact(env, "LEGAL_CONTACT_EMAIL", "adresse e-mail de contact")}. Vous pouvez aussi introduire une réclamation auprès de la CNIL (<a href="https://www.cnil.fr" rel="noopener">www.cnil.fr</a>).</p>
<h2>Mentions légales</h2>
<p>Voir les <a href="${LEGAL_PATH}">mentions légales</a>.</p>`,
  );
}

/** Serves the public pages. Returns true when the request was handled. */
export function handlePublicPage(
  req: IncomingMessage,
  res: ServerResponse,
  path: string,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (req.method !== "GET" && req.method !== "HEAD") return false;
  let html: string;
  if (path === LEGAL_PATH) html = legalNotice(env);
  else if (path === PRIVACY_PATH) html = privacy(env);
  else if (path === "/" && String(req.headers.accept ?? "").includes("text/html")) html = home();
  else return false;
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
  });
  res.end(req.method === "HEAD" ? undefined : html);
  return true;
}
