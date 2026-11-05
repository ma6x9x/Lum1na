//
//  LuminaMindNet.swift — live Grok / Ollama connect path.
//  Phone never talks to MAC_LAN_IP or 192.168.1.1 (router).
//

import Foundation

enum LuminaMindNet {
    /// This lab Mac's Wi-Fi (en0). Discover / lastGood override it.
    static let labOllama = "http://192.168.1.236:11434/v1"
    static let grokBase = "https://api.x.ai/v1"
    static let lastGoodKey = "lumind.lastGood"

    static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.waitsForConnectivity = true
        c.timeoutIntervalForRequest = 180
        c.timeoutIntervalForResource = 240
        c.allowsConstrainedNetworkAccess = true
        c.allowsExpensiveNetworkAccess = true
        c.httpAdditionalHeaders = ["User-Agent": "Lum1na-Debugger"]
        return URLSession(configuration: c)
    }()

    static func lastGood() -> String? {
        let s = UserDefaults.standard.string(forKey: lastGoodKey)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if s.isEmpty { return nil }
        if LuminaMindSettings.isPlaceholder(s) { return nil }
        return s
    }

    static func remember(_ url: String) {
        let t = url.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard !t.isEmpty, !LuminaMindSettings.isPlaceholder(t) else { return }
        UserDefaults.standard.set(t, forKey: lastGoodKey)
    }

    static func chatTimeout(provider: LuminaMindProvider) -> TimeInterval {
        switch provider {
        case .spacexai, .openrouter: return 180
        case .ollama, .lan, .custom: return 150
        }
    }

    static func resolvedOllamaBase(current: String) -> String {
        if !LuminaMindSettings.isPlaceholder(current),
           current.contains("11434") || current.contains("8081") || current.contains("8080") {
            return current.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        }
        if let good = lastGood(), good.contains("11434") || good.contains("808") {
            return good
        }
        return labOllama
    }

    /// Key on the settings object, else Documents/xai_key.txt. Never the Grok CLI token.
    static func liveKey(_ settings: LuminaMindSettings) -> String {
        let k = settings.apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if !k.isEmpty { return k }
        return LuminaMindSettings.loadDroppedKey()
    }

    final class HTTPBox {
        var data: Data?
        var status = 0
        var transport = ""
    }

    struct HTTPResult {
        var data: Data?
        var status: Int
        var transport: String
    }

    static func http(_ req: URLRequest, wait: TimeInterval) -> HTTPResult {
        let box = HTTPBox()
        let sem = DispatchSemaphore(value: 0)
        session.dataTask(with: req) { d, resp, err in
            box.data = d
            box.status = (resp as? HTTPURLResponse)?.statusCode ?? 0
            box.transport = err?.localizedDescription ?? ""
            sem.signal()
        }.resume()
        let ok = sem.wait(timeout: .now() + wait)
        if ok == .timedOut && box.status == 0 && box.transport.isEmpty {
            box.transport = "timeout \(Int(wait))s"
        }
        return HTTPResult(data: box.data, status: box.status, transport: box.transport)
    }

    static func apiError(data: Data?, status: Int, transport: String) -> String {
        if let data, let obj = try? JSONSerialization.jsonObject(with: data) {
            if let d = obj as? [String: Any] {
                if let s = d["error"] as? String, !s.isEmpty {
                    let code = d["code"] as? String ?? ""
                    return "HTTP \(status) \(code) \(s)".trimmingCharacters(in: .whitespaces)
                }
                if let e = d["error"] as? [String: Any] {
                    let msg = (e["message"] as? String) ?? (e["type"] as? String) ?? ""
                    if !msg.isEmpty { return "HTTP \(status) \(msg)" }
                }
            }
        }
        if let data, let raw = String(data: data, encoding: .utf8), !raw.isEmpty {
            return "HTTP \(status) \(raw.prefix(280))"
        }
        if !transport.isEmpty {
            var t = "HTTP \(status) \(transport)"
            let low = transport.lowercased()
            if low.contains("offline") || low.contains("network") || low.contains("not connected") {
                t += " — Allow Local Network for Lum1na-Debugger (Settings → Privacy)."
            }
            return t
        }
        return "HTTP \(status)"
    }

    static func decorate(_ req: inout URLRequest, apiKey: String, openrouter: Bool) {
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Lum1na-Debugger", forHTTPHeaderField: "User-Agent")
        let key = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if !key.isEmpty {
            req.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization")
        }
        if openrouter {
            req.setValue("https://github.com/ma6x9x/Lum1na", forHTTPHeaderField: "HTTP-Referer")
            req.setValue("Lum1na-Mind", forHTTPHeaderField: "X-Title")
        }
    }

    static func decorate(_ req: inout URLRequest, settings: LuminaMindSettings, apiKey: String? = nil) {
        let or = settings.provider == .openrouter || settings.baseURL.contains("openrouter.ai")
        decorate(&req, apiKey: apiKey ?? liveKey(settings), openrouter: or)
    }

    /// Grok / OpenAI may send content as a string or as [{type,text}] parts.
    static func messageText(_ msg: [String: Any]) -> String? {
        if let s = msg["content"] as? String, !s.isEmpty { return s }
        if let arr = msg["content"] as? [[String: Any]] {
            let t = arr.compactMap { part -> String? in
                if let s = part["text"] as? String, !s.isEmpty { return s }
                return nil
            }.joined()
            if !t.isEmpty { return t }
        }
        if let s = msg["reasoning_content"] as? String, !s.isEmpty { return s }
        if let refusal = msg["refusal"] as? String, !refusal.isEmpty {
            return "refusal: \(refusal)"
        }
        return msg["content"] as? String
    }
}
