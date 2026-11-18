import SwiftUI

struct SummaryView: View {
    let summary: TermsSummary

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                riskTally
                ForEach(Array(summary.sortedPoints.enumerated()), id: \.element.id) { index, point in
                    PointCard(number: index + 1, point: point)
                }
                Text("AI-generated summary, not legal advice. Check the full text before relying on any point.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .padding(.top, 8)
            }
            .padding()
        }
        .background(Color(.systemGroupedBackground))
        .navigationTitle(summary.companyName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ShareLink(item: summary.shareText)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(summary.overallRisk.label, systemImage: summary.overallRisk.symbol)
                .font(.caption.bold())
                .padding(.horizontal, 10).padding(.vertical, 5)
                .background(summary.overallRisk.color.opacity(0.15), in: Capsule())
                .foregroundStyle(summary.overallRisk.color)
            Text(summary.documentType)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Text(summary.verdict)
                .font(.title3.weight(.semibold))
        }
    }

    private var riskTally: some View {
        HStack(spacing: 8) {
            ForEach(RiskLevel.allCases, id: \.self) { level in
                let n = summary.points.filter { $0.risk == level }.count
                if n > 0 {
                    Text("\(n) \(level.label.lowercased())")
                        .font(.caption)
                        .padding(.horizontal, 8).padding(.vertical, 4)
                        .background(level.color.opacity(0.12), in: Capsule())
                        .foregroundStyle(level.color)
                }
            }
        }
    }
}

private struct PointCard: View {
    let number: Int
    let point: KeyPoint
    @State private var showQuote = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Image(systemName: point.risk.symbol)
                    .foregroundStyle(point.risk.color)
                Text(point.category.uppercased())
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Text("#\(number)")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            Text(point.headline)
                .font(.headline)
            Text(point.explanation)
                .font(.body)
                .foregroundStyle(.primary.opacity(0.85))
            if !point.quote.isEmpty {
                DisclosureGroup("What it actually says", isExpanded: $showQuote) {
                    Text("“\(point.quote)”")
                        .font(.callout.italic())
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.top, 4)
                }
                .font(.footnote)
                .tint(.secondary)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 14))
        .overlay(alignment: .leading) {
            UnevenRoundedRectangle(topLeadingRadius: 14, bottomLeadingRadius: 14)
                .fill(point.risk.color)
                .frame(width: 5)
        }
    }
}
