import Foundation
import PDFKit
import UIKit

/// Turns a URL, PDF or text file into plain text for the model.
enum TextExtractor {
    static func text(fromWebPage url: URL) async throws -> String {
        var request = URLRequest(url: url)
        request.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
                         forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        let mime = (response as? HTTPURLResponse)?.mimeType ?? ""
        if mime == "application/pdf" || url.pathExtension.lowercased() == "pdf" {
            return text(fromPDFData: data)
        }
        let html = String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
        return await htmlToText(html)
    }

    static func text(fromFile url: URL) throws -> String {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        let data = try Data(contentsOf: url)
        if url.pathExtension.lowercased() == "pdf" {
            return text(fromPDFData: data)
        }
        return String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
    }

    static func text(fromPDFData data: Data) -> String {
        guard let doc = PDFDocument(data: data) else { return "" }
        return (0..<doc.pageCount).compactMap { doc.page(at: $0)?.string }.joined(separator: "\n")
    }

    /// Strips scripts/styles, then lets UIKit's HTML importer render the remaining text.
    @MainActor
    static func htmlToText(_ html: String) -> String {
        var cleaned = html
        for tag in ["script", "style", "noscript", "svg", "nav", "footer", "header"] {
            cleaned = cleaned.replacingOccurrences(
                of: "<\(tag)[^>]*>[\\s\\S]*?</\(tag)>",
                with: " ",
                options: [.regularExpression, .caseInsensitive])
        }
        if let data = cleaned.data(using: .utf8),
           let attributed = try? NSAttributedString(
               data: data,
               options: [.documentType: NSAttributedString.DocumentType.html,
                         .characterEncoding: String.Encoding.utf8.rawValue],
               documentAttributes: nil) {
            return collapse(attributed.string)
        }
        let noTags = cleaned.replacingOccurrences(of: "<[^>]+>", with: " ", options: .regularExpression)
        return collapse(noTags)
    }

    private static func collapse(_ s: String) -> String {
        s.replacingOccurrences(of: "[ \\t]+", with: " ", options: .regularExpression)
         .replacingOccurrences(of: "\\n\\s*\\n+", with: "\n\n", options: .regularExpression)
         .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
