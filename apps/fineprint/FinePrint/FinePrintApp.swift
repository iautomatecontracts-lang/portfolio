import SwiftUI

@main
struct FinePrintApp: App {
    @State private var history = HistoryStore()

    var body: some Scene {
        WindowGroup {
            TabView {
                SummarizeView()
                    .tabItem { Label("Summarize", systemImage: "doc.text.magnifyingglass") }
                HistoryView()
                    .tabItem { Label("History", systemImage: "clock") }
                SettingsView()
                    .tabItem { Label("Settings", systemImage: "gear") }
            }
            .environment(history)
        }
    }
}
