# openilink-app-echo

A minimal test App for OpenILink Hub. Echoes messages and commands back.

## Commands

| Command | Description |
|---------|-------------|
| `/echo <text>` | Immediately echo back the text |
| `/echo-delay <text>` | Reply after 5 seconds via Bot API |
| `/ping` | Reply with "pong!" |

## Setup

1. Create an App on OpenILink Hub:
   - Name: Echo
   - Slug: echo
   - Commands: `/echo`, `/echo-delay`, `/ping`
   - Events: `message.text`
   - Scopes: `messages.send`

2. Install the App to a Bot, copy `app_token` and `signing_secret`

3. Run:
```bash
export HUB_URL=https://hub.example.com
export HUB_APP_TOKEN=app_xxx
export HUB_SIGNING_SECRET=xxx
go run .
```

4. Set the installation's request_url to `http://localhost:8081/hub/webhook`

5. Verify URL, then test by sending `/echo hello` in WeChat.
