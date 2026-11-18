import SwiftUI

struct HistoryView: View {
    @Environment(HistoryStore.self) private var history

    var body: some View {
        NavigationStack {
            Group {
                if history.items.isEmpty {
                    ContentUnavailableView("No summaries yet",
                                           systemImage: "doc.text",
                                           description: Text("Summaries you create show up here."))
                } else {
                    List {
                        ForEach(history.items) { item in
                            NavigationLink(value: item) {
                                HStack(spacing: 12) {
                                    Image(systemName: item.overallRisk.symbol)
                                        .foregroundStyle(item.overallRisk.color)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(item.companyName).font(.headline)
                                        Text(item.documentType)
                                            .font(.subheadline).foregroundStyle(.secondary)
                                        Text(item.createdAt, style: .date)
                                            .font(.caption).foregroundStyle(.tertiary)
                                    }
                                }
                            }
                        }
                        .onDelete { history.delete(at: $0) }
                    }
                }
            }
            .navigationTitle("History")
            .navigationDestination(for: TermsSummary.self) { SummaryView(summary: $0) }
        }
    }
}

struct SettingsView: View {
    @State private var apiKey = KeychainStore.load()
    @State private var saved = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("sk-ant-…", text: $apiKey)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button(saved ? "Saved" : "Save key") {
                        KeychainStore.save(apiKey.trimmingCharacters(in: .whitespacesAndNewlines))
                        saved = true
                    }
                    .disabled(saved)
                } header: {
                    Text("Anthropic API key")
                } footer: {
                    Text("Stored in the iOS Keychain on this device only. Get a key at console.anthropic.com.")
                }
                .onChange(of: apiKey) { saved = false }

                Section("About") {
                    LabeledContent("Model", value: ClaudeClient.model)
                    Text("FinePrint sends the document text to Anthropic's API to produce the summary. Summaries are AI-generated and are not legal advice.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Settings")
        }
    }
}
