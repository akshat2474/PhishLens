# Design Rules (ai-design-skills)

All web UI and interface design in this project must strictly comply with the `landing-page-design` and `design-to-motion` specifications from `elayadesign/ai-design-skills`.

## Strict Visual Rules

### 1. Typography
- **Fonts**: Use only **Geist**, **Manrope**, **Geist Mono**, or **Poppins**.
- **Forbidden**: Never use Inter, Roboto, Arial, Open Sans, or Helvetica.
- **No italics**: Never use italic fonts anywhere.
- **One typeface per site**: Geist Mono is allowed alongside primary font only for code, data, or numeric UI.
- **Weights**: Never use ultra bold weights (900/black). Cap at semibold (600) or bold (700).
- **Copy rules**:
  - **No hyphens in text**: Do not use `-` inside body copy, headings, or labels. Rewrite phrases without hyphens.
  - **No orphaned words**: Apply `text-wrap: balance` for headings and `text-wrap: pretty` for body copy.
  - **Sentence case**: All headings, tabs, and buttons must use sentence case (never ALL CAPS).
- **Type scale**: Snap strictly to Tailwind type scale:
  - `text-xs`: 12px (line height 16px)
  - `text-sm`: 14px (line height 20px)
  - `text-base`: 16px (line height 24px)
  - `text-lg`: 18px (line height 28px)
  - `text-xl`: 20px (line height 28px)
  - `text-2xl`: 24px (line height 32px)
  - `text-3xl`: 30px (line height 36px)
  - `text-4xl`: 36px (line height 40px)
  - `text-5xl`: 48px (line height 1)

### 2. Spacing
Use only these exact token values (nothing between them, nothing outside them):
`0`, `2px`, `4px`, `8px`, `12px`, `16px`, `24px`, `32px`, `40px`, `48px`, `64px`, `80px`, `96px`.
- Main buttons: 8px vertical padding, 12px horizontal padding.

### 3. Corner Radius
- Only Tailwind radius values (`rounded-none`, `rounded-sm`: 2px, `rounded`: 4px, `rounded-md`: 6px, `rounded-lg`: 8px, `rounded-xl`: 12px, `rounded-2xl`: 16px, `rounded-3xl`: 24px, `rounded-full`).
- **Nested radius formula**: `inner radius = outer radius - gap` (when gap < 32px and result > 2).

### 4. Borders and Backgrounds
- **Never apply a border to only one side of a card.** Borders go all the way around or not at all.
- **Never use gradients in backgrounds.** Backgrounds are 100% flat.
- **Dark mode background colors**: Use only `#000000`, `#181818`, `#1F1F1F`, `#272727`, `#313131`, or `#131209`.

### 5. Hero & Text Gradient
- Heading gradient: `#FFFFFF` → `#9B9B9B` (the only place gradients are permitted, and strictly on text, never backgrounds).
- Heading and subheading max width: capped at 680px with line breaks at meaningful thoughts.

### 6. Banned Filler Words
Never write: "revolutionize", "supercharge", "cutting edge", "effortless", "transform your workflow", "take it to the next level", "harness the power", "world class". State what the system does in calm, plain, direct terms.
