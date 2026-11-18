import Foundation
import SwiftUI

/// How much a clause should worry the person agreeing to it.
enum RiskLevel: String, Codable, CaseIterable {
    case high
    case medium
    case low

    var label: String {
        switch self {
        case .high: "Red flag"
        case .medium: "Watch out"
        case .low: "Standard"
        }
    }

    var color: Color {
        switch self {
        case .high: .red
        case .medium: .orange
        case .low: .green
        }
    }

    var symbol: String {
        switch self {
        case .high: "exclamationmark.octagon.fill"
        case .medium: "exclamationmark.triangle.fill"
        case .low: "checkmark.seal.fill"
        }
    }

    var sortOrder: Int {
        switch self {
        case .high: 0
        case .medium: 1
        case .low: 2
        }
    }
}

/// One of the 5–10 things that matter.
struct KeyPoint: Codable, Identifiable, Hashable {
    var id = UUID()
    let category: String
    let headline: String
    let explanation: String
    let quote: String
    let risk: RiskLevel

    enum CodingKeys: String, CodingKey {
        case category, headline, explanation, quote, risk
    }
}

/// The full result for one document.
struct TermsSummary: Codable, Identifiable, Hashable {
    var id = UUID()
    var createdAt = Date()
    var source: String
    let companyName: String
    let documentType: String
    let verdict: String
    let overallRisk: RiskLevel
    var points: [KeyPoint]

    enum CodingKeys: String, CodingKey {
        case id, createdAt, source
        case companyName = "company_name"
        case documentType = "document_type"
        case verdict
        case overallRisk = "overall_risk"
        case points
    }

    /// Decoding from Claude's JSON: id/createdAt/source aren't in the model output.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = (try? c.decode(UUID.self, forKey: .id)) ?? UUID()
        createdAt = (try? c.decode(Date.self, forKey: .createdAt)) ?? Date()
        source = (try? c.decode(String.self, forKey: .source)) ?? ""
        companyName = try c.decode(String.self, forKey: .companyName)
        documentType = try c.decode(String.self, forKey: .documentType)
        verdict = try c.decode(String.self, forKey: .verdict)
        overallRisk = try c.decode(RiskLevel.self, forKey: .overallRisk)
        points = try c.decode([KeyPoint].self, forKey: .points)
    }

    var sortedPoints: [KeyPoint] {
        points.sorted { $0.risk.sortOrder < $1.risk.sortOrder }
    }

    var shareText: String {
        var lines = ["\(companyName) – \(documentType)", verdict, ""]
        for p in sortedPoints {
            lines.append("• [\(p.risk.label)] \(p.headline): \(p.explanation)")
        }
        lines.append("")
        lines.append("Summarized with FinePrint. Not legal advice.")
        return lines.joined(separator: "\n")
    }
}
