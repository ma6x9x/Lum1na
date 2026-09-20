import SwiftUI
import CoreGraphics

// MARK: - Swift port of Siri27 Shared/LGLiquidMotion.h
// Rubber-band center, overshoot stretch, and frame-step lerp for liquid drag.

struct LiquidDragState {
    var centerX: CGFloat
    var width: CGFloat
    var height: CGFloat
    var rubberBandOffset: CGFloat
}

struct LiquidRenderedState {
    var centerX: CGFloat
    var width: CGFloat
    var height: CGFloat
}

enum LiquidBubbleMotion {
    /// Rubber-band past [minX, maxX] with sqrt falloff (LGLiquidRubberBandedCenterX).
    static func rubberBandedCenterX(
        _ touchX: CGFloat,
        minX: CGFloat,
        maxX: CGFloat,
        factor: CGFloat = 1.24
    ) -> CGFloat {
        if touchX < minX {
            return minX - sqrt(minX - touchX) * factor
        }
        if touchX > maxX {
            return maxX + sqrt(touchX - maxX) * factor
        }
        return touchX
    }

    static func overshootDistance(
        _ touchX: CGFloat,
        minX: CGFloat,
        maxX: CGFloat
    ) -> CGFloat {
        if touchX < minX { return minX - touchX }
        if touchX > maxX { return touchX - maxX }
        return 0
    }

    /// Full drag sample with velocity-based stretch (LGLiquidDragStateMake).
    static func dragState(
        touchX: CGFloat,
        minX: CGFloat,
        maxX: CGFloat,
        baseSize: CGSize,
        velocity: CGFloat,
        minHeight: CGFloat
    ) -> LiquidDragState {
        var state = LiquidDragState(
            centerX: rubberBandedCenterX(touchX, minX: minX, maxX: maxX, factor: 1.24),
            width: baseSize.width,
            height: baseSize.height,
            rubberBandOffset: 0
        )

        if touchX < minX {
            state.rubberBandOffset = state.centerX - minX
        } else if touchX > maxX {
            state.rubberBandOffset = state.centerX - maxX
        }

        let overshoot = overshootDistance(touchX, minX: minX, maxX: maxX)
        let normalizedVelocity = min(abs(velocity) / 900.0, 1.0)
        let motionStretch = pow(normalizedVelocity, 0.71)
        let directionalBias: CGFloat = velocity >= 0 ? 1.0 : -1.0
        let overshootBias = min(overshoot / 16.0, 1.0)
        let widthBoost = 19.5 * motionStretch + 5.8 * overshootBias
        let heightReduction = 5.4 * motionStretch + 1.8 * overshootBias
        let xShift = directionalBias * (5.1 * motionStretch + 2.4 * overshootBias)

        state.centerX += xShift
        state.width += widthBoost
        state.height = max(minHeight, state.height - heightReduction)
        return state
    }

    static func renderedState(centerX: CGFloat, size: CGSize) -> LiquidRenderedState {
        LiquidRenderedState(centerX: centerX, width: size.width, height: size.height)
    }

    /// Frame-step lerp toward target (LGLiquidRenderedStateStep).
    static func step(
        current: LiquidRenderedState,
        target: LiquidRenderedState,
        active: Bool,
        dt: CGFloat
    ) -> LiquidRenderedState {
        let frameFactor = min(max(dt * 60.0, 0.35), 1.4)
        let centerLerp = (active ? 0.21 : 0.14) * frameFactor
        let sizeLerp = (active ? 0.25 : 0.15) * frameFactor
        var next = current
        next.centerX += (target.centerX - current.centerX) * centerLerp
        next.width += (target.width - current.width) * sizeLerp
        next.height += (target.height - current.height) * sizeLerp
        return next
    }

    /// 2D rubber-band of a free offset inside a circular bound (bubble hero).
    static func rubberBandedOffset(
        _ translation: CGSize,
        maxRadius: CGFloat,
        factor: CGFloat = 1.24
    ) -> CGSize {
        let length = hypot(translation.width, translation.height)
        guard length > maxRadius, length > 0 else { return translation }
        let excess = length - maxRadius
        let banded = maxRadius + sqrt(excess) * factor
        let scale = banded / length
        return CGSize(width: translation.width * scale, height: translation.height * scale)
    }

    /// Velocity/overshoot stretch scales for a circular bubble.
    static func bubbleStretch(
        translation: CGSize,
        velocity: CGSize,
        maxRadius: CGFloat
    ) -> (scaleX: CGFloat, scaleY: CGFloat) {
        let length = hypot(translation.width, translation.height)
        let overshoot = max(0, length - maxRadius)
        let speed = hypot(velocity.width, velocity.height)
        let normalizedVelocity = min(speed / 900.0, 1.0)
        let motionStretch = pow(normalizedVelocity, 0.71)
        let overshootBias = min(overshoot / 16.0, 1.0)
        let widthBoost = (19.5 * motionStretch + 5.8 * overshootBias) / 158.0
        let heightReduction = (5.4 * motionStretch + 1.8 * overshootBias) / 158.0
        return (1.0 + widthBoost, max(0.86, 1.0 - heightReduction))
    }
}

/// Observable drag state for the glass bubble hero.
final class LiquidBubbleMotionState: ObservableObject {
    @Published var offset: CGSize = .zero
    @Published var scaleX: CGFloat = 1
    @Published var scaleY: CGFloat = 1
    @Published var isDragging = false

    /// Soft bound radius before rubber-band begins.
    var maxRadius: CGFloat = 36

    private var dragOrigin: CGSize = .zero

    func beginDrag() {
        isDragging = true
        dragOrigin = offset
    }

    func updateDrag(translation: CGSize, velocity: CGSize = .zero) {
        let raw = CGSize(
            width: dragOrigin.width + translation.width,
            height: dragOrigin.height + translation.height
        )
        offset = LiquidBubbleMotion.rubberBandedOffset(raw, maxRadius: maxRadius)
        let stretch = LiquidBubbleMotion.bubbleStretch(
            translation: offset,
            velocity: velocity,
            maxRadius: maxRadius
        )
        scaleX = stretch.scaleX
        scaleY = stretch.scaleY
    }

    func endDrag() {
        isDragging = false
        withAnimation(.spring(response: 0.42, dampingFraction: 0.72)) {
            offset = .zero
            scaleX = 1
            scaleY = 1
        }
    }
}
