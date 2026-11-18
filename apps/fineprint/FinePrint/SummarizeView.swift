import SwiftUI
import UniformTypeIdentifiers

struct SummarizeView: View {
    enum InputMode: String, CaseIterable, Identifiable {
        case paste = "Paste text"
        case link = "Link"
        var id: String { rawValue }
    }

    @Environment(HistoryStore.self) private var history
    @State private var mode: InputMode = .paste
    @State private var pastedText = ""
    @State private var link = ""
    @State private var isImporting = false
    @State private var isWorking = false
    @State private var status = ""
    @State private var errorMessage: String?
    @State private var result: TermsSummary?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Input", selection: $mode) {
                        ForEach(InputMode.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                }

                switch mode {
                case .paste:
                    Section {
                        TextEditor(text: $pastedText)
                            .frame(minHeight: 220)
                            .overlay(alignment: .topLeading) {
                                if pastedText.isEmpty {
                                    Text("Paste the terms & conditions or privacy policy here…")
                                        .foregroundStyle(.tertiary)
                                        .padding(.top, 8)
                                        .padding(.leading, 4)
                                        .allowsHitTesting(false)
                                }
                            }
                        HStack {
                            Button("Paste from clipboard", systemImage: "doc.on.clipboard") {
                                pastedText = UIPasteboard.general.string ?? ""
                            }
                            Spacer()
                            Button("Import file", systemImage: "folder") { isImporting = true }
                        }
                        .buttonStyle(.borderless)
                        .font(.subheadline)
                    } footer: {
                        Text("\(pastedText.count.formatted()) characters")
                    }
                case .link:
                    Section {
                        TextField("https://example.com/terms", text: $link)
                            .keyboardType(.URL)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    } footer: {
                        Text("Works with most public terms, privacy-policy and PDF links.")
                    }
                }

                Section {
                    Button {
                        Task { await run() }
                    } label: {
                        HStack {
                            Spacer()
                            if isWorking {
                                ProgressView().padding(.trailing, 6)
                                Text(status)
                            } else {
                                Label("Tell me what matters", systemImage: "sparkles")
                                    .fontWeight(.semibold)
                            }
                            Spacer()
                        }
                    }
                    .disabled(isWorking || !hasInput)
                }

                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "xmark.octagon")
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("FinePrint")
            .navigationDestination(item: $result) { SummaryView(summary: $0) }
            .fileImporter(isPresented: $isImporting,
                          allowedContentTypes: [.pdf, .plainText, .html, .rtf, .text]) { outcome in
                importFile(outcome)
            }
        }
    }

    private var hasInput: Bool {
        switch mode {
        case .paste: !pastedText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .link: URL(string: normalizedLink)?.host != nil
        }
    }

    private var normalizedLink: String {
        let t = link.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.lowercased().hasPrefix("http") ? t : "https://\(t)"
    }

    private func importFile(_ outcome: Result<URL, Error>) {
        do {
            let url = try outcome.get()
            pastedText = try TextExtractor.text(fromFile: url)
            errorMessage = pastedText.isEmpty ? "Couldn't find any text in that file." : nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    @MainActor
    private func run() async {
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }
        do {
            let text: String
            let source: String
            switch mode {
            case .paste:
                text = pastedText
                source = "Pasted text"
            case .link:
                guard let url = URL(string: normalizedLink) else { return }
                status = "Fetching page…"
                text = try await TextExtractor.text(fromWebPage: url)
                source = url.absoluteString
                if text.count < 500 {
                    throw SummarizerError.badResponse(
                        "That page had very little text (it may need JavaScript). Copy the text and paste it instead.")
                }
            }
            status = "Reading the fine print…"
            let client = ClaudeClient(apiKey: KeychainStore.load())
            let summary = try await client.summarize(text, source: source)
            history.add(summary)
            result = summary
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

#Preview {
    SummarizeView().environment(HistoryStore())
}
