import SwiftUI
import UIKit

/// In-app Peek inspector — SwiftPeek's discovery logic, running in-process.
///
/// Pre-commit this peeks LUM1NA's own view tree (the only process we can
/// touch from a stock app). Post-commit the same logic ships injected in
/// ANY app via SwiftPeek/SPKit — this view is the in-app twin, kept deliberately
/// API-identical in spirit: hosting-view discovery + Swift type naming.
///
/// No private APIs. No probes invoked. Console-only evidence.
enum PeekInspector {

    private static let maxDepth = 5
    private static let maxLines = 40

    /// Walk Lum1na's own windows; report hosting views + Swift type names.
    static func dump(into log: (String) -> Void) {
        var lines: [String] = []
        var budget = maxLines
        var hosting = 0
        var windows = 0

        for scene in UIApplication.shared.connectedScenes {
            guard let ws = scene as? UIWindowScene else { continue }
            for window in ws.windows {
                windows += 1
                lines.append("[peek] window level=\(Int(window.windowLevel.rawValue)) key=\(window.isKeyWindow)")
                walk(window, depth: 0, into: &lines, hosting: &hosting, budget: &budget)
            }
        }
        lines.append("[peek] done: windows=\(windows) hosting=\(hosting) (in-process twin of SPHostingViewsIn)")

        for l in lines { log(l) }
    }

    private static func walk(_ view: UIView, depth: Int,
                             into lines: inout [String],
                             hosting: inout Int,
                             budget: inout Int) {
        guard budget > 0, depth <= maxDepth else { return }
        let cls = NSStringFromClass(type(of: view))

        if cls.contains("UIHosting") {
            hosting += 1
            budget -= 1
            let frame = view.frame
            lines.append(String(format: "[peek] %@ {{%.0f,%.0f %.0fx%.0f}} d%d",
                                cls, frame.origin.x, frame.origin.y,
                                frame.size.width, frame.size.height, depth))
            // Swift side of the translation layer: read the hosting
            // controller's rootView through the runtime mirror.
            var vc: UIViewController? = nil
            var r: UIResponder? = view
            while r != nil, vc == nil {
                r = r?.next
                if let c = r as? UIViewController { vc = c }
            }
            if let vc {
                let m = Mirror(reflecting: vc)
                for child in m.children where child.label == "rootView" {
                    let t = String(describing: type(of: child.value))
                    lines.append("[peek]   rootView: \(t)")
                    budget -= 1
                    mirrorChildren(child.value, depth: 0, into: &lines, budget: &budget)
                }
            }
        } else if cls.contains("NavigationController") || cls.contains("TabBarController") {
            budget -= 1
            lines.append("[peek] \(cls) d\(depth)")
        }

        for sub in view.subviews {
            walk(sub, depth: depth + 1, into: &lines, hosting: &hosting, budget: &budget)
        }
    }

    /// Mirror a SwiftUI value's immediate children (the "type names" half of
    /// SPSwiftMeta, public-API flavored). One level only — SwiftUI trees are
    /// deep; we show the shape, not the whole forest.
    private static func mirrorChildren(_ value: Any, depth: Int,
                                       into lines: inout [String],
                                       budget: inout Int) {
        guard budget > 0, depth < 2 else { return }
        let m = Mirror(reflecting: value)
        var shown = 0
        for child in m.children {
            guard shown < 6, budget > 0 else { break }
            let t = String(describing: type(of: child.value))
            let label = child.label ?? "~"
            lines.append("[peek]     \(String(repeating: " ", count: depth))\(label): \(t)")
            budget -= 1
            shown += 1
            if !(t.hasPrefix("Color") || t.hasPrefix("Font") || t.hasPrefix("EdgeInsets")) {
                mirrorChildren(child.value, depth: depth + 1, into: &lines, budget: &budget)
            }
        }
    }
}