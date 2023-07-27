## RemoteEarlyBird

Payload rc4 encrypted shellcode retrieved from remote server via HTTP.

Remote Mapping Injection is used to allocate a Memory region mapped to the encrypted payload. Payload is then decrypted on local process, thus decrypting the remote payload as well.

New process created in debug mode, for APC Injection to queue execution on the main thread.

### Usage

`encremmap <url> <process>` -> Fetches payload from `<url>`, creates new `<process>` to perform mapping injection on encrypted payload and queues the main thread for an APC and detaches from the remote process.