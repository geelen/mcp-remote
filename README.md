# `mcp-remote`

Connect an MCP Client that only supports local (stdio) servers to a Remote MCP Server, with auth support:

**Note: this is a working proof-of-concept** but should be considered **experimental**.

## Why is this necessary?

So far, the majority of MCP servers in the wild are installed locally, using the stdio transport. This has some benefits: both the client and the server can implicitly trust each other as the user has granted them both permission to run. Adding secrets like API keys can be done using environment variables and never leave your machine. And building on `npx` and `uvx` has allowed users to avoid explicit install steps, too.

But there's a reason most software that _could_ be moved to the web _did_ get moved to the web: it's so much easier to find and fix bugs & iterate on new features when you can push updates to all your users with a single deploy.

With the MCP [Authorization specification](https://spec.modelcontextprotocol.io/specification/draft/basic/authorization/) nearing completion, we now have a secure way of sharing our MCP servers with the world _without_ running code on user's laptops. Or at least, you would, if all the popular MCP _clients_ supported it yet. Most are stdio-only, and those that _do_ support HTTP+SSE don't yet support the OAuth flows required.

That's where `mcp-remote` comes in. As soon as your chosen MCP client supports remote, authorized servers, you can remove it. Until that time, drop in this one liner and dress for the MCP clients you want!

## Usage

### Claude Desktop

[Official Docs](https://modelcontextprotocol.io/quickstart/user)

In order to add an MCP server to Claude Desktop you need to edit the configuration file located at:

macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

Windows: `%APPDATA%\Claude\claude_desktop_config.json`

If it does not exist yet, [you may need to enable it under Settings > Developer](https://modelcontextprotocol.io/quickstart/user#2-add-the-filesystem-mcp-server).

```json
{
  "mcpServers": {
    "remote-example": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ]
    }
  }
}
```

Restart Claude Desktop to pick up the changes in the configuration file.
Upon restarting, you should see a hammer icon in the bottom right corner
of the input box.

### Cursor

[Official Docs](https://docs.cursor.com/context/model-context-protocol)

Add the following configuration to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "remote-example": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ]
    }
  }
}
```

### Windsurf

[Official Docs](https://docs.codeium.com/windsurf/mcp)

Add the following configuration to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "remote-example": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ]
    }
  }
}
```

## Building Remote MCP Servers

For instructions on building & deploying remote MCP servers, including acting as a valid OAuth client, see the following resources:

* https://developers.cloudflare.com/agents/guides/remote-mcp-server/

In particular, see:

* https://github.com/cloudflare/workers-oauth-provider for defining an MCP-comlpiant OAuth server in Cloudflare Workers
* https://github.com/cloudflare/agents/tree/main/examples/mcp for defining an `McpAgent` using the [`agents`](https://npmjs.com/package/agents) framework.

For more information about testing these servers, see also:

* https://developers.cloudflare.com/agents/guides/test-remote-mcp-server/

Know of more resources you'd like to share? Please add them to this Readme and send a PR!

## Debugging

### Check your Node version

Make sure that the version of Node you have installed is [16 or 
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

[Follow Claude Desktop logs in real-time](https://modelcontextprotocol.io/docs/tools/debugging#debugging-in-claude-desktop)

MacOS / Linux:

`tail -n 20 -F ~/Library/Logs/Claude/mcp*.log`

For bash on WSL:

`tail -n 20 -f "C:\Users\YourUsername\AppData\Local\Claude\Logs\mcp.log"`

or Powershell:

`Get-Content "C:\Users\YourUsername\AppData\Local\Claude\Logs\mcp.log" -Wait -Tail 20`


## Debugging

If you encounter the following error, returned by the `/callback` URL:

```
Authentication Error
Token exchange failed: HTTP 400
```

You can run `rm -rf ~/.mcp-auth` to clear any locally stored state and tokens.
