import Foundation

enum SummarizerError: LocalizedError {
    case missingAPIKey
    case emptyInput
    case http(Int, String)
    case refused
    case truncated
    case badResponse(String)

    var errorDescription: String? {
        switch self {
        case .missingAPIKey: "Add your Anthropic API key in Settings first."
        case .emptyInput: "There's no text to summarize."
        case .http(let code, let msg): "Request failed (\(code)): \(msg)"
        case .refused: "The model declined to summarize this text."
        case .truncated: "The summary was cut off. Try again."
        case .badResponse(let msg): "Couldn't read the summary: \(msg)"
        }
    }
}

/// Calls the Claude Messages API over raw HTTP (there is no official Swift SDK).
struct ClaudeClient {
    static let model = "claude-opus-5-5"
    private let endpoint = URL(string: "https://api.anthropic.com/v1/messages")!

    let apiKey: String

    private static let systemPrompt = """
    You read terms of service, terms and conditions, privacy policies, EULAs and similar \
    contracts on behalf of an ordinary consumer who is about to click "I agree" without reading.

    Your job: pick the 5 to 10 things in THIS document that most affect that person, and explain \
    each one in plain, everyday English (aim for an 8th-grade reading level, no legalese).

    Prioritize, roughly in this order, whatever the document actually contains:
    - Giving up the right to sue: forced arbitration, class-action waivers, jury-trial waivers, opt-out windows
    - Money: auto-renewal, free trials that convert to paid, cancellation hurdles, refunds, hidden fees, price changes
    - Personal data: what is collected (location, contacts, biometrics, messages), selling or sharing with \
      third parties/advertisers/data brokers, cross-site tracking, use for AI training, how long it's kept, whether you can delete it
    - Your content: licenses the company takes over what you upload or create (perpetual, irrevocable, \
      sublicensable, commercial use), ownership of your work
    - Unilateral changes: the company can change terms or prices at any time, "continued use means acceptance"
    - Account termination or content removal without notice or reason; what you lose
    - Liability caps and disclaimers that leave you with little recourse
    - Governing law / venue far from the user; indemnification the user owes the company
    - Anything unusual, surprising or unusually aggressive for this kind of service

    Rules:
    - Only report what the text actually says. Never invent a clause. If something important (like \
      arbitration) is notably ABSENT, you may mention that as a low-risk point.
    - Each headline is short (under 10 words) and states the consequence for the user, e.g. \
      "You can't sue them in court".
    - Each explanation is 1–3 sentences: what it means for the person and, when one exists, what they can \
      do about it (e.g. "You can opt out by emailing X within 30 days").
    - quote: a short verbatim excerpt (under 30 words) from the document backing the point. Use "" if the point is about an absence.
    - risk: "high" for things that strip rights, cost money unexpectedly, or sell/share sensitive data; \
      "medium" for notable but common terms; "low" for reassuring or standard terms.
    - Order points from most to least important.
    - verdict: one or two sentences giving the bottom line.
    - If the text is not a terms/policy document, still return the JSON with document_type "Not a terms document", \
      a verdict that says so, and at least one point explaining what the text appears to be.
    """

    private static let schema: [String: Any] = [
        "type": "object",
        "properties": [
            "company_name": ["type": "string"],
            "document_type": ["type": "string"],
            "verdict": ["type": "string"],
            "overall_risk": ["type": "string", "enum": ["high", "medium", "low"]],
            "points": [
                "type": "array",
                "items": [
                    "type": "object",
                    "properties": [
                        "category": ["type": "string"],
                        "headline": ["type": "string"],
                        "explanation": ["type": "string"],
                        "quote": ["type": "string"],
                        "risk": ["type": "string", "enum": ["high", "medium", "low"]],
                    ],
                    "required": ["category", "headline", "explanation", "quote", "risk"],
                    "additionalProperties": false,
                ],
            ],
        ],
        "required": ["company_name", "document_type", "verdict", "overall_risk", "points"],
        "additionalProperties": false,
    ]

    func summarize(_ text: String, source: String) async throws -> TermsSummary {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw SummarizerError.emptyInput }
        guard !apiKey.isEmpty else { throw SummarizerError.missingAPIKey }

        let body: [String: Any] = [
            "model": Self.model,
            "max_tokens": 16000,
            "system": Self.systemPrompt,
            "output_config": [
                "effort": "medium",
                "format": ["type": "json_schema", "schema": Self.schema],
            ],
            // If a safety classifier declines, let the API retry on a fallback model in the same call.
            "fallbacks": "default",
            "messages": [[
                "role": "user",
                "content": "Source: \(source)\n\n<document>\n\(trimmed)\n</document>",
            ]],
        ]

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 300
        request.setValue("application/json", forHTTPHeaderField: "content-type")
        request.setValue(apiKey, forHTTPHeaderField: "x-api-key")
        request.setValue("2026-10-21", forHTTPHeaderField: "anthropic-version")
        request.setValue("server-side-fallback-2026-07-01", forHTTPHeaderField: "anthropic-beta")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw SummarizerError.http(status, Self.errorMessage(from: data))
        }

        let message = try JSONDecoder().decode(APIMessage.self, from: data)
        switch message.stopReason {
        case "refusal": throw SummarizerError.refused
        case "max_tokens": throw SummarizerError.truncated
        default: break
        }
        guard let json = message.content.first(where: { $0.type == "text" })?.text,
              let jsonData = json.data(using: .utf8) else {
            throw SummarizerError.badResponse("no text in response")
        }
        do {
            var summary = try JSONDecoder().decode(TermsSummary.self, from: jsonData)
            summary.source = source
            summary.points = Array(summary.points.prefix(10))
            return summary
        } catch {
            throw SummarizerError.badResponse(error.localizedDescription)
        }
    }

    private static func errorMessage(from data: Data) -> String {
        if let err = try? JSONDecoder().decode(APIErrorEnvelope.self, from: data) {
            return err.error.message
        }
        return String(data: data, encoding: .utf8) ?? "unknown error"
    }
}

private struct APIMessage: Decodable {
    struct Block: Decodable {
        let type: String
        let text: String?
    }
    let content: [Block]
    let stopReason: String?

    enum CodingKeys: String, CodingKey {
        case content
        case stopReason = "stop_reason"
    }
}

private struct APIErrorEnvelope: Decodable {
    struct Inner: Decodable { let message: String }
    let error: Inner
}
