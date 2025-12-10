# Troubleshooting

## Auth Storage

Credentials are stored in `~/.mcp-auth/mcp-remote/` (or `{MCP_REMOTE_CONFIG_DIR}/mcp-remote/` if set).

**Version-agnostic storage (default):** Tokens persist across mcp-remote updates. No re-authentication needed when the package updates.

**Version-specific storage:** Set `MCP_REMOTE_VERSIONED_CONFIG=1` to use version-specific directories like `~/.mcp-auth/mcp-remote-0.1.31/` (useful for development/testing).

### Clearing Credentials

If you're having persistent auth issues, try clearing stored credentials:

```sh
rm -rf ~/.mcp-auth/mcp-remote
```

Then restart your MCP client.

## Check your Node version

Make sure that the version of Node you have installed is [18 or
higher](https://modelcontextprotocol.io/quickstart/server). Claude
Desktop will use your system version of Node, even if you have a newer
version installed elsewhere.

## Restart Claude

When modifying `claude_desktop_config.json` it can helpful to completely restart Claude.

## VPN Certs

You may run into issues if you are behind a VPN, you can try setting the `NODE_EXTRA_CA_CERTS`
environment variable to point to the CA certificate file. If using `claude_desktop_config.json`,
this might look like:

```json
{
  "mcpServers": {
    "remote-example": {
      "command": "npx",
      "args": ["mcp-remote", "https://remote.mcp.server/sse"],
      "env": {
        "NODE_EXTRA_CA_CERTS": "{your CA certificate file path}.pem"
      }
    }
  }
}
```

## Check the logs

- [Follow Claude Desktop logs in real-time](https://modelcontextprotocol.io/docs/tools/debugging#debugging-in-claude-desktop)
- MacOS / Linux:<br/>`tail -n 20 -F ~/Library/Logs/Claude/mcp*.log`
- For bash on WSL:<br/>`tail -n 20 -f "C:\Users\YourUsername\AppData\Local\Claude\Logs\mcp.log"`
- Powershell: <br/>`Get-Content "C:\Users\YourUsername\AppData\Local\Claude\Logs\mcp.log" -Wait -Tail 20`

# Debugging

## Debug Logs

For troubleshooting complex issues, especially with token refreshing or authentication problems, use the `--debug` flag:

```json
"args": [
  "mcp-remote",
  "https://remote.mcp.server/sse",
  "--debug"
]
```

This creates detailed logs in `~/.mcp-auth/{server_hash}_debug.log` with timestamps and complete information about every step of the connection and authentication process. When you find issues with token refreshing, laptop sleep/resume issues, or auth problems, provide these logs when seeking support.

## Authentication Errors

If you encounter the following error, returned by the `/callback` URL:

```
Authentication Error
Token exchange failed: HTTP 400
```

You can run `rm -rf ~/.mcp-auth` to clear any locally stored state and tokens.

## "Client" mode

Run the following on the command line (not from an MCP server):

```shell
npx -p mcp-remote@latest mcp-remote-client https://remote.mcp.server/sse
```

This will run through the entire authorization flow and attempt to list the tools & resources at the remote URL. Try this after running `rm -rf ~/.mcp-auth` to see if stale credentials are your problem, otherwise hopefully the issue will be more obvious in these logs than those in your MCP client.
