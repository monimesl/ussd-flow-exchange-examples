# Security Test Flow Definition

This is the USSD flow JSON that you import into the Monime dashboard to test your exchange server's encryption implementation.

## Flow Structure

The flow has 3 pages:

1. **`security_test_start`** — A `dynamic` page that immediately calls your exchange server. Your server responds with the menu data.
2. **`security_test_menu`** — A `menu` page that displays options (Continue / Cancel). On selection, fires an `exchange` action to your server.
3. **`security_test_result`** — A `display` page that shows the result message. On done, fires a final `exchange` to your server.

```
[security_test_start] → dynamic call → server responds with menu
        ↓
[security_test_menu] → subscriber picks "Continue" or "Cancel" → exchange call
        ↓
[security_test_result] → shows result → exchange call → server says "stop"
```

## Setup

1. Open `security-test-flow.json`
2. Replace all `YOUR_SERVER_URL` with your deployed server URL
3. Import the flow into the Monime dashboard
4. Add your RSA public key in the flow's Security section
5. Publish and test via USSD

## What Your Server Should Return

| `currentPage` | Expected response |
|---|---|
| `security_test_start` | `navigate` to `security_test_menu` with menu items |
| `security_test_menu` | `navigate` to `security_test_result` (if continue) or `stop` (if cancel) |
| `security_test_result` | `stop` with a thank you message |

See any of the language implementations in this repo for the complete handler logic.
