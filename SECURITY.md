# Security notes

- Use only trusted HTTPS source URLs and authorized feeds.
- Never put passwords, app passwords, or API keys in source control.
- Do not run this agent as Administrator/root unless strictly necessary (it is not necessary for normal use).
- The agent only parses feed text and structured vulnerability metadata; it does not retrieve or execute exploit payloads.
- Treat all RSS and external content as untrusted data. Verify claims before response.
- Restrict filesystem access to the project and its `data/` directory.
