"""
Generate ADLockoutBuster.ico — multi-resolution Windows icon.
Design: dark-blue shield, white padlock body, red alert dot in top-right.
Run once:  python make_icon.py
"""
from PIL import Image, ImageDraw, ImageFilter
import math

def draw_icon(size: int) -> Image.Image:
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d   = ImageDraw.Draw(img)

    pad  = max(1, s // 16)
    cx   = s / 2

    # ── Background: rounded square, dark navy ──────────────────────
    bg_color = (13, 17, 23, 255)      # #0d1117
    r_bg = max(2, s // 7)
    d.rounded_rectangle([pad, pad, s - pad - 1, s - pad - 1],
                        radius=r_bg, fill=bg_color)

    # ── Shield body ───────────────────────────────────────────────
    # Simple shield = pentagon-ish polygon
    sh_left  = s * 0.18
    sh_right = s * 0.82
    sh_top   = s * 0.10
    sh_mid   = s * 0.62   # where sides start to taper
    sh_bot   = s * 0.92

    shield = [
        (cx,        sh_top),
        (sh_right,  sh_top + (sh_mid - sh_top) * 0.3),
        (sh_right,  sh_mid),
        (cx,        sh_bot),
        (sh_left,   sh_mid),
        (sh_left,   sh_top + (sh_mid - sh_top) * 0.3),
    ]

    # Glow / shadow layer
    if s >= 48:
        glow_img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        gd = ImageDraw.Draw(glow_img)
        gd.polygon(shield, fill=(31, 111, 235, 80))
        glow_img = glow_img.filter(ImageFilter.GaussianBlur(radius=max(1, s // 20)))
        img = Image.alpha_composite(img, glow_img)
        d = ImageDraw.Draw(img)

    # Shield fill — blue gradient faked as two rects
    d.polygon(shield, fill=(21, 80, 180, 255))   # base
    # Lighter top half
    top_half = [
        (cx,        sh_top),
        (sh_right,  sh_top + (sh_mid - sh_top) * 0.3),
        (sh_right,  sh_mid * 0.55),
        (cx,        sh_mid * 0.55),
        (sh_left,   sh_mid * 0.55),
        (sh_left,   sh_top + (sh_mid - sh_top) * 0.3),
    ]
    d.polygon(top_half, fill=(31, 111, 235, 200))

    # Shield border
    bw = max(1, s // 24)
    d.line(shield + [shield[0]], fill=(88, 166, 255, 220), width=bw)

    # ── Padlock body ──────────────────────────────────────────────
    lk_w   = s * 0.32
    lk_h   = s * 0.26
    lk_x   = cx - lk_w / 2
    lk_y   = s * 0.47
    lk_r   = max(2, int(lk_w * 0.15))
    d.rounded_rectangle(
        [lk_x, lk_y, lk_x + lk_w, lk_y + lk_h],
        radius=lk_r,
        fill=(230, 237, 243, 255),
        outline=(255, 255, 255, 180),
        width=max(1, s // 40)
    )

    # Keyhole
    kh_r  = max(1, int(lk_w * 0.13))
    kh_cx = int(cx)
    kh_cy = int(lk_y + lk_h * 0.40)
    d.ellipse([kh_cx - kh_r, kh_cy - kh_r, kh_cx + kh_r, kh_cy + kh_r],
              fill=(21, 80, 180, 255))
    stem_w = max(1, kh_r // 2 + 1)
    stem_h = max(2, int(lk_h * 0.28))
    d.rectangle([kh_cx - stem_w, kh_cy + kh_r - 1,
                 kh_cx + stem_w, kh_cy + kh_r + stem_h],
                fill=(21, 80, 180, 255))

    # ── Shackle (arch above lock body) ────────────────────────────
    sk_w   = lk_w * 0.52
    sk_h   = lk_h * 0.85
    sk_x   = cx - sk_w / 2
    sk_y   = lk_y - sk_h
    sk_lw  = max(2, s // 20)
    d.arc([sk_x, sk_y, sk_x + sk_w, sk_y + sk_h * 1.4],
          start=180, end=0,
          fill=(230, 237, 243, 255), width=sk_lw)

    # ── Alert dot — red circle, top-right of shield ───────────────
    dot_r  = max(3, s // 9)
    dot_cx = int(sh_right * 0.88)
    dot_cy = int(sh_top   * 1.45)

    # White halo
    d.ellipse([dot_cx - dot_r - 2, dot_cy - dot_r - 2,
               dot_cx + dot_r + 2, dot_cy + dot_r + 2],
              fill=(13, 17, 23, 255))
    # Red fill
    d.ellipse([dot_cx - dot_r, dot_cy - dot_r,
               dot_cx + dot_r, dot_cy + dot_r],
              fill=(239, 68, 68, 255))
    # Exclamation mark (only at larger sizes)
    if s >= 48:
        ew  = max(1, dot_r // 4)
        eh1 = max(2, int(dot_r * 0.9))
        ey  = dot_cy - dot_r // 2 - eh1 + 1
        d.rectangle([dot_cx - ew, ey, dot_cx + ew, ey + eh1],
                    fill=(255, 255, 255, 255))
        ed = max(1, ew)
        d.ellipse([dot_cx - ed, dot_cy + dot_r // 4 - ed,
                   dot_cx + ed, dot_cy + dot_r // 4 + ed],
                  fill=(255, 255, 255, 255))

    return img


if __name__ == "__main__":
    sizes   = [256, 128, 64, 48, 32, 16]
    frames  = [draw_icon(s) for s in sizes]

    out = "ADLockoutBuster.ico"
    frames[0].save(
        out,
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=frames[1:],
    )
    print(f"Created {out}  ({len(sizes)} sizes: {sizes})")

    # Also export a 256x256 PNG for reference
    frames[0].save("ADLockoutBuster_256.png")
    print("Also saved ADLockoutBuster_256.png (preview)")
