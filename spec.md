# Basic MCP-enabled Chat Application

The goal of this project is to demonstrate a basic MCP client, capable of handling 
authorization via the MCP spec at https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization.

Specifically, we want to ensure we're capable of handling [dynamic client registration](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#dynamic-client-registration).

What I'd like to build here is something like this:

1. A basic chat bot, encapsulated within a server.
  1. An encapsulated MCP client package.
  2. A conversation loop, backed by OpenAI's apis, that can use the tools offered by arbitrary MCP servers.
2. A basic web client that can interface with the server.

Let's use:
1. go for the server and MCP client.
2. postgres for the server-side database.
3. a websocket to connect from the client to the server.
4. A basic static javascript client.

Leverage the MCP Go SDK, the openai Go sdk.

Ensure there's authentication between the client and the server. 

Write a readme describing how to connect to an arbitrary example MCP server (perhaps google calendar.)