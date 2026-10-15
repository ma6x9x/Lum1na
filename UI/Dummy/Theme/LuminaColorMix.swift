//
//  LuminaColorMix.swift
//  Lum1na
//
//  Deployment target is 17.0 (12 mini iOS 17.3 is the lowest fleet OS),
//  but Color.mix(with:by:) is iOS 18+. This helper branches on
//  availability and lerps RGBA manually below 18 so the Dummy theme
//  compiles and renders identically on 17.3. On iOS 18+ it forwards to
//  the native mix, so glass/tint color math is unchanged everywhere.
//

import SwiftUI
import UIKit

func luminaMix(_ base: Color, _ target: Color, by fraction: Double) -> Color {
    if #available(iOS 18.0, *) {
        return base.mix(with: target, by: fraction)
    }
    let f = min(max(fraction, 0), 1)
    var bR: CGFloat = 0, bG: CGFloat = 0, bB: CGFloat = 0, bA: CGFloat = 0
    var tR: CGFloat = 0, tG: CGFloat = 0, tB: CGFloat = 0, tA: CGFloat = 0
    guard UIColor(base).getRed(&bR, green: &bG, blue: &bB, alpha: &bA),
          UIColor(target).getRed(&tR, green: &tG, blue: &tB, alpha: &tA) else {
        return base // non-RGBA color (named/semantic) — degrade honestly
    }
    return Color(red: Double(bR + (tR - bR) * f),
                 green: Double(bG + (tG - bG) * f),
                 blue: Double(bB + (tB - bB) * f),
                 opacity: Double(bA + (tA - bA) * f))
}