# `mcp-remote`

Connect an MCP Client that only supports local (stdio) servers to a Remote MCP Server, with auth support:

**Note: this is a working proof-of-concept** but should be considered **experimental**.

## Why is this necessary?

So far, the majority of MCP servers in the wild are installed locally, using the stdio transport. This has some benefits: both the client and the server can implicitly trust each other as the user has granted them both permission to run. Adding secrets like API keys can be done using environment variables and never leave your machine. And building on `npx` and `uvx` has allowed users to avoid explicit install steps, too.

But there's a reason most software that _could_ be moved to the web _did_ get moved to the web: it's so much easier to find and fix bugs & iterate on new features when you can push updates to all your users with a single deploy.

With the latest MCP [Authorization specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization), we now have a secure way of sharing our MCP servers with the world _without_ running code on user's laptops. Or at least, you would, if all the popular MCP _clients_ supported it yet. Most are stdio-only, and those that _do_ support HTTP+SSE don't yet support the OAuth flows required.

That's where `mcp-remote` comes in. As soon as your chosen MCP client supports remote, authorized servers, you can remove it. Until that time, drop in this one liner and dress for the MCP clients you want!

## Usage

All the most popular MCP clients (Claude Desktop, Cursor & Windsurf) use the following config format:

```json
{
  "mcpServers": {
    "remote-example": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ]
    }
  }
}
```

### Custom Headers

To bypass authentication, or to emit custom headers on all requests to your remote server, pass `--header` CLI arguments:

```json
{
  "mcpServers": {
    "remote-example": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "--header",
        "Authorization: Bearer ${AUTH_TOKEN}"
      ],
      "env": {
        "AUTH_TOKEN": "..."
      }
    },
  }
}
```

**Note:** Cursor and Claude Desktop (Windows) have a bug where spaces inside `args` aren't escaped when it invokes `npx`, which ends up mangling these values. You can work around it using:

```jsonc
{
  // rest of config...
  "args": [
    "mcp-remote",
    "https://remote.mcp.server/sse",
    "--header",
    "Authorization:${AUTH_HEADER}" // note no spaces around ':'
  ],
  "env": {
    "AUTH_HEADER": "Bearer <auth-token>" // spaces OK in env vars
  }
},
```

### Flags

* If `npx` is producing errors, consider adding `-y` as the first argument to auto-accept the installation of the `mcp-remote` package.

```json
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ]
```

* To force `npx` to always check for an updated version of `mcp-remote`, add the `@latest` flag:

```json
      "args": [
        "mcp-remote@latest",
        "https://remote.mcp.server/sse"
      ]
```

* To change which port `mcp-remote` listens for an OAuth redirect (by default `3334`), add an additional argument after the server URL. Note that whatever port you specify, if it is unavailable an open port will be chosen at random.

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "9696"
      ]
```

* To allow HTTP connections in trusted private networks, add the `--allow-http` flag. Note: This should only be used in secure private networks where traffic cannot be intercepted.

```json
      "args": [
        "mcp-remote",
        "http://internal-service.vpc/sse",
        "--allow-http"
      ]
```

### Transport Strategies

MCP Remote supports different transport strategies when connecting to an MCP server. This allows you to control whether it uses Server-Sent Events (SSE) or HTTP transport, and in what order it tries them.

Specify the transport strategy with the `--transport` flag:

```bash
npx mcp-remote https://example.remote/server --transport sse-only
```

**Available Strategies:**

- `http-first` (default): Tries HTTP transport first, falls back to SSE if HTTP fails with a 404 error
- `sse-first`: Tries SSE transport first, falls back to HTTP if SSE fails with a 405 error
- `http-only`: Only uses HTTP transport, fails if the server doesn't support it
- `sse-only`: Only uses SSE transport, fails if the server doesn't support it

### Post-Auth Redirect URI

To customize the redirect behavior after an OAuth flow, include a `postAuthRedirectUri` query parameter in the request to the OAuth callback endpoint. This parameter specifies where users should be redirected after successful authentication.

Ensure that your server appends `postAuthRedirectUri` as a query parameter when invoking the `redirectUri`.

Once authentication is complete, users will be redirected to the specified URI instead of seeing the default "Authorization successful" message. This allows you to deliver a smoother user experience by guiding users to a custom post-authentication page.

### Claude Desktop

[Official Docs](https://modelcontextprotocol.io/quickstart/user)

In order to add an MCP server to Claude Desktop you need to edit the configuration file located at:

* macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
* Windows: `%APPDATA%\Claude\claude_desktop_config.json`

If it does not exist yet, [you may need to enable it under Settings > Developer](https://modelcontextprotocol.io/quickstart/user#2-add-the-filesystem-mcp-server).

Restart Claude Desktop to pick up the changes in the configuration file.
Upon restarting, you should see a hammer icon in the bottom right corner
of the input box.

### Cursor

[Official Docs](https://docs.cursor.com/context/model-context-protocol). The configuration file is located at `~/.cursor/mcp.json`.

As of version `0.48.0`, Cursor supports unauthed SSE servers directly. If your MCP server is using the official MCP OAuth authorization protocol, you still need to add a **"command"** server and call `mcp-remote`.

### Windsurf

[Official Docs](https://docs.codeium.com/windsurf/mcp). The configuration file is located at `~/.codeium/windsurf/mcp_config.json`.

## Building Remote MCP Servers

For instructions on building & deploying remote MCP servers, including acting as a valid OAuth client, see the following resources:

* https://developers.cloudflare.com/agents/guides/remote-mcp-server/

In particular, see:

* https://github.com/cloudflare/workers-oauth-provider for defining an MCP-comlpiant OAuth server in Cloudflare Workers
* https://github.com/cloudflare/agents/tree/main/examples/mcp for defining an `McpAgent` using the [`agents`](https://npmjs.com/package/agents) framework.

For more information about testing these servers, see also:

* https://developers.cloudflare.com/agents/guides/test-remote-mcp-server/

Know of more resources you'd like to share? Please add them to this Readme and send a PR!

## Troubleshooting

### Clear your `~/.mcp-auth` directory

`mcp-remote` stores all the credential information inside `~/.mcp-auth` (or wherever your `MCP_REMOTE_CONFIG_DIR` points to). If you're having persistent issues, try running:

```sh
rm -rf ~/.mcp-auth
```

Then restarting your MCP client.

### Check your Node version

Make sure that the version of Node you have installed is [18 or 
higher](https://modelcontextprotocol.io/quickstart/server). Claude
Desktop will use your system version of Node, even if you have a newer
version installed elsewhere.

### Restart Claude

When modifying `claude_desktop_config.json` it can helpful to completely restart Claude

### VPN Certs

You may run into issues if you are behind a VPN, you can try setting the `NODE_EXTRA_CA_CERTS`
environment variable to point to the CA certificate file. If using `claude_desktop_config.json`,
this might look like:

```json
{
 "mcpServers": {
    "remote-example": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ],
      "env": {
        "NODE_EXTRA_CA_CERTS": "{your CA certificate file path}.pem"
      }
    }
  }
}
```

### Check the logs

* [Follow Claude Desktop logs in real-time](https://modelcontextprotocol.io/docs/tools/debugging#debugging-in-claude-desktop)
* MacOS / Linux:<br/>`tail -n 20 -F ~/Library/Logs/Claude/mcp*.log`
* For bash on WSL:<br/>`tail -n 20 -f "C:\Users\YourUsername\AppData\Local\Claude\Logs\mcp.log"`
* Powershell: <br/>`Get-Content "C:\Users\YourUsername\AppData\Local\Claude\Logs\mcp.log" -Wait -Tail 20`

## Debugging

If you encounter the following error, returned by the `/callback` URL:

```
Authentication Error
Token exchange failed: HTTP 400
```

You can run `rm -rf ~/.mcp-auth` to clear any locally stored state and tokens.

### "Client" mode

Run the following on the command line (not from an MCP server):

```shell
npx -p mcp-remote@latest mcp-remote-client https://remote.mcp.server/sse
```

This will run through the entire authorization flow and attempt to list the tools & resources at the remote URL. Try this after running `rm -rf ~/.mcp-auth` to see if stale credentials are your problem, otherwise hopefully the issue will be more obvious in these logs than those in your MCP client.
