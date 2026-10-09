import SwiftUI

/// The unlit board: grid, field traces, fan-out traces, triple-line buses,
/// vias, pads, IC footprints, chip legs, connector fingers and legibility
/// scrims. `Equatable` on the layout generation so it redraws only when the
/// geometry or appearance changes, never per progress tick.
struct BoardStaticLayer: View, Equatable {
    let layout: BoardLayout
    let generation: Int
    let isDark: Bool

    nonisolated static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.generation == rhs.generation && lhs.isDark == rhs.isDark
    }

    var body: some View {
        Canvas { context, _ in
            draw(in: &context)
        }
        .accessibilityHidden(true)
    }

    private func draw(in context: inout GraphicsContext) {
        let colors = BoardColors(scheme: isDark ? .dark : .light)
        let size = layout.size
        let hero = layout.hero
        let full = CGRect(origin: .zero, size: size)

        context.fill(Path(full), with: .radialGradient(
            Gradient(colors: [colors.baseCenter, colors.base]),
            center: hero.center, startRadius: 10, endRadius: size.height * 0.8
        ))

        var grid = Path()
        var x: CGFloat = 0
        while x < size.width { grid.move(to: CGPoint(x: x + 0.25, y: 0)); grid.addLine(to: CGPoint(x: x + 0.25, y: size.height)); x += 12 }
        var y: CGFloat = 0
        while y < size.height { grid.move(to: CGPoint(x: 0, y: y + 0.25)); grid.addLine(to: CGPoint(x: size.width, y: y + 0.25)); y += 12 }
        context.stroke(grid, with: .color(colors.grid), lineWidth: 0.5)

        let round = StrokeStyle(lineWidth: 1, lineCap: .round, lineJoin: .round)
        context.stroke(layout.fieldPath, with: .color(colors.field), style: round)
        var fanStyle = round
        fanStyle.lineWidth = 1.25
        context.stroke(layout.fanPath, with: .color(colors.trace), style: fanStyle)

        // Buses: wide stroke, gap, centre line → reads as a three-line bus.
        for bus in layout.buses {
            context.stroke(bus.path, with: .color(colors.bus), style: StrokeStyle(lineWidth: 8, lineCap: .round, lineJoin: .round))
            context.stroke(bus.path, with: .color(colors.busGap), style: StrokeStyle(lineWidth: 5.6, lineCap: .round, lineJoin: .round))
            context.stroke(bus.path, with: .color(colors.bus), style: StrokeStyle(lineWidth: 1.3, lineCap: .round, lineJoin: .round))
        }

        for via in layout.vias {
            let rect = CGRect(x: via.center.x - via.radius, y: via.center.y - via.radius, width: via.radius * 2, height: via.radius * 2)
            context.fill(Path(ellipseIn: rect), with: .color(colors.busGap))
            context.stroke(Path(ellipseIn: rect), with: .color(colors.via), lineWidth: 1.1)
        }
        for pad in layout.pads {
            context.fill(Path(CGRect(x: pad.x - 2.5, y: pad.y - 2.5, width: 5, height: 5)), with: .color(colors.pad))
        }

        for ic in layout.ics {
            var pins = Path()
            var px = ic.minX + 4
            while px < ic.maxX - 2 {
                pins.addRect(CGRect(x: px - 1, y: ic.minY - 4, width: 2, height: 4))
                pins.addRect(CGRect(x: px - 1, y: ic.maxY, width: 2, height: 4))
                px += 6
            }
            context.fill(pins, with: .color(colors.pin))
            let body = Path(roundedRect: ic, cornerRadius: 2)
            context.fill(body, with: .color(colors.icBody))
            context.stroke(body, with: .color(colors.icEdge), lineWidth: 0.8)
            context.fill(Path(ellipseIn: CGRect(x: ic.minX + 2.5, y: ic.minY + 2.5, width: 2, height: 2)), with: .color(colors.icEdge))
        }

        var legs = Path()
        for leg in layout.legs {
            if leg.normal.dx != 0 {
                legs.addRect(CGRect(x: leg.origin.x + (leg.normal.dx > 0 ? 0 : -8), y: leg.origin.y - 1.3, width: 8, height: 2.6))
            } else {
                legs.addRect(CGRect(x: leg.origin.x - 1.3, y: leg.origin.y + (leg.normal.dy > 0 ? 0 : -8), width: 2.6, height: 8))
            }
        }
        context.fill(legs, with: .color(colors.leg))

        var fingers = Path()
        for finger in layout.fingers { fingers.addRect(finger) }
        context.fill(fingers, with: .color(colors.pin))

        // Scrims: calm the board behind the header and the controls.
        let top = hero.bounds.minY + 8
        context.fill(Path(CGRect(x: 0, y: 0, width: size.width, height: top)), with: .linearGradient(
            Gradient(colors: [colors.base.opacity(0.78), colors.base.opacity(0)]),
            startPoint: .zero, endPoint: CGPoint(x: 0, y: top)
        ))
        let fadeStart = hero.bounds.maxY - 30
        context.fill(Path(CGRect(x: 0, y: fadeStart, width: size.width, height: size.height - fadeStart)), with: .linearGradient(
            Gradient(colors: [colors.base.opacity(0), colors.base.opacity(0.55)]),
            startPoint: CGPoint(x: 0, y: fadeStart), endPoint: CGPoint(x: 0, y: fadeStart + 70)
        ))
    }
}
