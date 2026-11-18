# FinePrint

An iOS app that reads terms & conditions, privacy policies and EULAs and tells you the 5–10 things that actually matter, ranked by risk and written in plain English.

## What it flags
- **Your right to sue:** forced arbitration, class-action waivers, opt-out windows
- **Money:** auto-renewal, trials that turn into paid plans, cancellation hurdles, fees, price changes
- **Your data:** what's collected, selling/sharing with advertisers, tracking, AI training, deletion
- **Your content:** licenses the company takes over what you upload
- **Unilateral changes:** "we can change these terms at any time"
- **Termination:** account or content removal without notice
- **Liability caps, indemnification, governing law**

Each point gets a 🔴 / 🟠 / 🟢 risk level, a short headline, a plain explanation (including how to opt out when that's possible), and the exact quote it's based on.

## Run it
1. Install **Xcode 16 or later** from the Mac App Store.
2. Open `FinePrint.xcodeproj`.
3. Select the FinePrint target → Signing & Capabilities → choose your Team (and change the bundle ID from `com.example.FinePrint` if you need to).
4. Pick an iPhone simulator and press ⌘R.
5. In the app, open **Settings** and paste an Anthropic API key (from console.anthropic.com).

## How it works
- Input: paste text, import a PDF/text file, or enter a link (the page or PDF is fetched and converted to text on the device).
- `ClaudeClient.swift` sends the text to the Claude Messages API (`claude-opus-5-5`) with a JSON schema, so the reply is always structured data.
- The API key lives in the iOS Keychain. Summaries are saved to History on the device.

## Files
| File | Purpose |
|---|---|
| `ClaudeClient.swift` | API call, system prompt (what counts as "matters"), JSON schema |
| `Models.swift` | `TermsSummary`, `KeyPoint`, `RiskLevel` |
| `TextExtractor.swift` | URL / HTML / PDF → plain text |
| `Stores.swift` | Keychain key storage, saved history |
| `SummarizeView.swift`, `SummaryView.swift`, `HistoryAndSettings.swift` | UI |

## Before shipping to the App Store
Each user pastes their own API key, which is fine for personal use. For a public app, put a small backend between the app and Anthropic so your key never ships inside the app.

Summaries are AI-generated and are not legal advice.
