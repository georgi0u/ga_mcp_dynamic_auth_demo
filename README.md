# MCP Authorization Demo

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


## Background

## OAuth and the MCP Auth Spec

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



