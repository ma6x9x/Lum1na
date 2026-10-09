import SwiftUI
import CoreText

/// The console typeface. CRT uses the bundled VT323 pixel font (SIL OFL,
/// registered at runtime, so no Info.plist entry is needed); Clean uses SF Mono.
enum TerminalFont {
    static let pixelFontName = "VT323-Regular"

    /// Registers the bundled pixel font for this process. Safe to call repeatedly.
    static func registerIfNeeded() {
        guard let url = Bundle.main.url(forResource: pixelFontName, withExtension: "ttf") else { return }
        CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
    }

    /// Dynamic-Type-scaling console font for the given style.
    static func font(_ style: ConsoleStyle, size: CGFloat, relativeTo textStyle: Font.TextStyle = .footnote) -> Font {
        switch style {
        case .crt: .custom(pixelFontName, size: size, relativeTo: textStyle)
        case .clean: .system(textStyle, design: .monospaced)
        }
    }
}
