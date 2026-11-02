import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { MailClient } from "./mail.js";

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };

const ok = (data: unknown): ToolResult => ({
  content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
});

const fail = (e: unknown): ToolResult => ({
  content: [{ type: "text", text: `Error: ${e instanceof Error ? e.message : String(e)}` }],
  isError: true,
});

/** Build a fresh MCP server exposing the mail tools. */
export function createServer(mail: MailClient): McpServer {
  const server = new McpServer({ name: "mailmcp", version: "0.1.0" });

  server.registerTool(
    "mail_list_folders",
    {
      title: "List mail folders",
      description: "List all folders of the mailbox with message and unread counts.",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    async () => {
      try {
        return ok(await mail.listFolders());
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "mail_search",
    {
      title: "Search emails",
      description:
        "Search emails in a folder. Returns summaries (UID, sender, subject, date, unread) newest first. Use mail_read with the UID to get the body.",
      inputSchema: {
        folder: z.string().default("INBOX").describe("Folder path, e.g. INBOX"),
        unread: z.boolean().optional().describe("Only unread messages"),
        text: z.string().optional().describe("Full-text search in headers and body"),
        from: z.string().optional().describe("Sender contains"),
        subject: z.string().optional().describe("Subject contains"),
        since: z.string().optional().describe("ISO date, only messages on/after this date"),
        limit: z.number().int().min(1).max(100).default(20).describe("Max results"),
      },
      annotations: { readOnlyHint: true },
    },
    async (args) => {
      try {
        return ok(await mail.search(args));
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "mail_read",
    {
      title: "Read an email",
      description: "Fetch the full content of an email by UID in a given folder.",
      inputSchema: {
        uid: z.number().int().positive().describe("Message UID from mail_search"),
        folder: z.string().default("INBOX").describe("Folder path"),
        mark_read: z.boolean().default(false).describe("Mark the message as read"),
      },
      annotations: { readOnlyHint: false },
    },
    async ({ uid, folder, mark_read }) => {
      try {
        return ok(await mail.read(uid, folder, mark_read));
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "mail_send",
    {
      title: "Send an email",
      description: "Send an email via SMTP. This sends immediately and cannot be undone.",
      inputSchema: {
        to: z.array(z.string().email()).min(1).describe("Recipients"),
        subject: z.string().min(1),
        text: z.string().describe("Plain text body"),
        cc: z.array(z.string().email()).optional(),
        bcc: z.array(z.string().email()).optional(),
        html: z.string().optional().describe("Optional HTML body"),
        in_reply_to: z.string().optional().describe("Message-ID being replied to"),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    async ({ to, subject, text, cc, bcc, html, in_reply_to }) => {
      try {
        return ok(await mail.send({ to, subject, text, cc, bcc, html, inReplyTo: in_reply_to }));
      } catch (e) {
        return fail(e);
      }
    },
  );

  return server;
}
