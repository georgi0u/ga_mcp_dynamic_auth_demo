# MCP Authorization Demo

## Video Demonstration

Check this video out to see me walk through some of what this does: 
https://www.loom.com/share/be8bf2e202a44caab3763943bb8b7084

## Peter's Prompt

> Grounded Agents Coding Project
> 
> Our goal in interviewing is to get as close to working together as possible, because that's what's 
> important to actually get signal on. This task allows for both some meaningful coding and creative 
> thinking at several levels.
>
> MCP Authorization Spec is a first attempt at adding authorization to the MCP protocol. While key 
> systems like Google Workspace warrant deeply imperative integrations, this spec and specifically 
> Dynamic Client Registration (DCR) unlock some powerful and newly dynamic access to the sea of 
> enterprise tools and datasets. It's interesting here for a couple reasons:
> 
> 1. It's something that is both kind of clear how it might work but also somewhat counter intuitive. 
>    You've got to dig around a bit to wrap your head around MCP to get the full auth callback cycle to
>    work.
> 2. It brings you into intersections with modern best practices for Identity / SSO / Identity
>    Providers / MCP clients, all of which are currently important concerns for us.
> 
> The use case is to build an MCP client that can dynamically self register to an MCP server and 
> then use its negotiated client_id to make an OAuth connection for a user of that system. We would
> specifically like you to use Claude Code or Codex (amongst any other AI tooling) to build out your
> solution.
> 
> Please let us know how this all sounds. The point is for you to finish the project with a clear 
> POV on how/when to use this approach, a working proof of concept we can easily run, and feeling 
> excited to work with LLM-driven development tools.


## Intro to my solution

To start, I used Codex to build this, backed by gpt-5.4 set to extra high thinking.

The structure is as follows:

1. A simple react/nextjs client that allows for a OpenAI-backed conversation and simple management of 
   MCP connections.
2. A go-based api server that does all the work, including establishing MCP connections via an MCP 
   client. i.e., the crux of what was asked for.
3. Postgres as a datastore.
4. Docker wraps and runs everything, for easy portability.


## To Run

1. Set client environment variables (e.g. hosts, ports). 
   * `cp ./client/.env.local.example ./client/.env.local`.
2. Set backend env variables. 
   * `cp ./server/.env.example ./server/.env`. 
   * You need to specify an OpenAI API key for the chat to work. Ping me if you need one.
3. Ensure docker desktop is installed/running. 
   * https://www.docker.com/products/docker-desktop/
4. Start the app.
   * (From the root directory): `docker compose up --build`
5. Visit `http://localhost:3000/` to play with the demo app.


# OAuth and the MCP Auth Spec

Let's assume the reader and I understand the more typical oauth use case. In summary, third parties and their 
APIs are unique, and thus need to be integrated with individually before the client can do anything 
useful on behalf of a user. e.g., a workout app wants to push workouts to Apple Health, and thus call
Apple Healths, "POST /activities" api. In this world, it's reasonable for the client to manually establish
a client_id (and secret) before attempting any work, because the client is going to have to write code
to handle the Apple Health API calls ahead of time anyway.

But what is a client_id? It's mostly a static association of a client application with some 
identifying metadata. It's used to scope a set of relationships, so that the third-party can revoke 
permissions en-masse, for any specific client. And it's used to identify the client application
to a user, when that user is prompted to authorize the client to do _stuff_.

However, if the third party doesn't do any additional authorization when establishing client_ids, 
this metadata is mostly just developer provided strings.

What happens if we remove the constraint of third-parties being unique? What if a whole series of arbitrary
servers implemented the same API, and a client wanted to offer integration with any of them, without knowing
any of those third parties before hand? Sounds a lot like MCP.


## Non-preregistered Client IDs

If we know what a whole class of servers is going to look like, we want to be able to register against any of them,
at runtime. How can we get a client id/relationship with the third party dynamically?

The prompt asks for an implementation of Dynamic Client Registration, but that's not actually 
recommended anymore. The recommended way is to have your client offer a persistent and widely 
available "Client ID Metadata Document" that the third-party auth server can use to initialize a client id for a client,
without extra steps/client-side maintenance.

Here's what I've learned of each:

## Dynamic Client Registration

Dynamic Client Registration works as follows: 

1. You assume the server does not require authentication and proceed..
2. If a request fails for permissions, and the response includes a www-authenticate header,
   which itself includes a resources_metadata URL. The data at that URL may include
   metadata that allows for ± dynamically fetching a client id.
3. You use that metadata to fetch a client_id (and client secret).
4. You can now use that client metadata to do "typical" oauth handshakes on behalf of users, in order
   to fetch access/refresh tokens. With those tokens in hand, you can talk to the third party 
   server on behalf of the user.

There are a few annoyances with this approach:

1. The client needs to maintain code to fetch client ids.
2. The client needs to persist client ids across all third-party servers.
3. The client needs to maintain code to ensure previously fetched client ids are consistent with
   the current auth server issuer. If the third party issuer changes, the client needs to detect that
   and refetch a new client_id. See: https://modelcontextprotocol.io/specification/draft/basic/authorization#authorization-server-binding.
    
Compare that to Client ID Metadata Documents:

### Client ID Metadata Document

1. The client maintains public a server endpoint that hosts a piece of metadata describing the client
   to all interested auth servers.
2. The client doesn't need to establish a client_id, explicitly anymore. Instead, the client issues
   the auth request for user access tokens, specifying the above URL as its client id.
3. The auth server determines if its seen the client before, and hits the above URL. Or otherwise,
   proceeds.

In this world, a few things are improved:
1. The auth issuer can then change, and the client doesn't need to know about it. The auth server can 
establish a new internal representation of the client as it sees fit.
2. The client doesn't need a pre-emptive handshake to establish a client_id.
3. The client doesn't need to store third-party specific client_ids.

However, this requires the client have a publicly accessible Client ID Document URL, which isn't
ideal for a take-home assignment hosted on localhost 🙃



# Implementation Explanation

The files immediately relevant to the assignment are in the [mcpservice](./server/internal/mcpservice/)
and [mcpclient](./server/internal/mcpclient/) go packages.

* `mcpclient`: Minimal dependency client that can do: client id fetching, auth token fetching, 
tool calls.
* `mcpservice`: A wrapper around the client that persists client ids and auth tokens to postgres.

I've annotated the above, inline in comments, explaining the implementation. 

Everything else is for serving a toy app that uses the client.


# Quirks

A few things I had to intervene with:

1. Codex initially tightly couple the data store and the client, which I felt went against the spirit
   of both Peter's initial prompt to me and mine to it. I wanted the client to be as standalone as 
   possible, and so had to (have codex) refactor.
2. Codex also tied client ids to auth tokens (i.e. individual connections), such that every connection
   had a new client_id. This is improper. The app should have one client id per mcp server auth server,
   and should reuse that client id during subsequent interactions with the auth server (unless the 
   issuer of the client id changes).
3. Initially only built out support for SSE style connections to MCP servers, when the new recommendation
   is to use http streaming. Certain servers only support one or the other. Prompted codex to refactor.
4. Codex didn't add validation to compare the stored issuer id, of an existing client_id, to the current
   issuer defined by the auth server. The spec reads that if these two vary, you should either error 
   or fetch a new client_id from the new issuer (and throw away the old one) (in the dynamic case).s
5. Codex didn't initially add PKCE or proper state handling to the auth flow. The MCP auth flow needs
   PKCE for the authorization code exchange, and the client should also generate and verify state on
   the callback to prevent callback forgery / request mixups. Refactored.

A few things I would do differently, but are prob. fine for a demo app:

1. Both the `mcpclient` and `mcpservice` expose each step of the auth process as standalone
   methods, to be called imperatively, at the application layer. I'd probably encapsulate this
   a bit tighter, so as to not require callers to handle each step one by one. Allowing for 
   individual calls provides more surface area for, e.g., handling the case where theres a 
   preregistered client id, rolling things back conditionally, handling errors with more context
   for where you are in the flow. That's a bit verbose for a demo app, but works well enough.
2. I'm encrypting all of my sensitive data, in application code, and generally handling auth in-house.
   I'd probably defer this to third-party tools (e.g. firebase auth). At minimum, my keys
   would be in a secret manager, not env variables.
3. The application server API is using a lot of standard library stuff, which is fine. I prefer
   go's gin framework for writing http servers. A bit less verbose, more out of the box.
4. The application server is managing database migrations inline. I'd decouple this to make
   migrations safer. I'd also use an ORM rather than relying on inline-sql strings. (go-bun is nice.)
5. I didn't look too deeply at the client side or conversation loop code. That's only there to 
   demo the client.

