# Recovery Vault illustration provenance

Generated on 2026-08-27 with the Google Gemini API. No API key, response payload,
or rejected candidate is stored in this repository.

## Generation configuration

- Model and returned model version: `gemini-3-pro-image`
- Endpoint: `v1beta/models/gemini-3-pro-image:generateContent`
- Response modalities: `TEXT`, `IMAGE`
- Requested image configuration: aspect ratio `3:2`, image size `2K`
- Search grounding: disabled
- Candidate count: two initial light candidates per concept
- Corrective edits: one each for `access-timeline`, `recovery-kit`, and
  `delayed-recovery`
- Total API image outputs: 24
- Style reference: selected `access-timeline-c` was supplied as a style-only
  reference for the other six initial light concepts
- Dark variants: palette-only reference edits of the selected light masters
- Normalization: opaque sRGB PNG, 720×480, metadata stripped with ImageMagick

## Selections and SHA-256

| Committed file | Selected Gemini output | SHA-256 |
|---|---|---|
| `access-timeline-light.png` | `access-timeline-c` (corrective edit of candidate A) | `2107030b3295ab51623c90a1f23bc5f5d5c0b82aeb0e1768f091a9e01b06634d` |
| `access-timeline-dark.png` | palette edit of selected light | `54c37758994b5ecaddb5fed28063580f7d7d2bdec636a19c6f16121ea51fb3c6` |
| `recovery-kit-light.png` | `recovery-kit-c` (corrective edit of candidate B) | `cb65b9ed53dc76de437f09bdabb0a8e8015920d3861018d60c5419300fc5a290` |
| `recovery-kit-dark.png` | palette edit of selected light | `2e4e3a5361f633cb4d2cb391b712703f26a213f3ffc3124a7c39d396765f680a` |
| `address-verification-light.png` | candidate A | `7e2dc834c66e384962aee6ec58e31d955cf794995c8c448c6ed113dec24e1c2e` |
| `address-verification-dark.png` | palette edit of selected light | `9c86d0224db262f2064ef7e3e439b407ec312492dfb11ecbae9b0b384f7d8d00` |
| `restore-authority-light.png` | candidate A | `654575c36fca9d81080f5502c758f67cea50aa36412a1225966be3059f87ae4a` |
| `restore-authority-dark.png` | palette edit of selected light | `a0df7f2f577d4ad59039de0979bf7da1e00ead7a05697bb098d8af7a45dabecb` |
| `delayed-recovery-light.png` | `delayed-recovery-c` (corrective edit of candidate B) | `8575844623f3b928f5231ed6a8185b9ca03fc6fae12da2d17a25aa4bb6d159d4` |
| `delayed-recovery-dark.png` | palette edit of selected light | `51197eee0d8e3a753c66eba9462c9e1098c781cd0364f556a744a00ffc53771a` |
| `protection-renewal-light.png` | candidate A | `ab55bffa6bd8f29be4ce1efce8980307fbb5ed4d41ae78eabe6c3b2aa1798090` |
| `protection-renewal-dark.png` | palette edit of selected light | `b9fe8239afdc569dbf3669d9ff250cdaaf5699aec4946e5ee3b7894d8feaf60b` |
| `vault-ready-light.png` | candidate A | `0ba181a4ca1c94d33a19a10f4b3d1f37427d855597e1da982b643bb67c0342df` |
| `vault-ready-dark.png` | palette edit of selected light | `e8bbb14c1637b6f7a682e02586e9eb6521d520ffe71bf33892bfdae661795846` |

## Exact prompts

The following are the complete prompt strings sent to Gemini. Repeated candidate
requests used the same applicable prompt.

### `access-timeline` initial candidates

```text
Use case: infographic-diagram
Asset type: compact in-product teaching panel for the Bitcoin Core Recovery Vault desktop UI
Primary request: visualize three-key immediate authority plus two additional delayed recovery paths without implying that the immediate path expires
Scene/backdrop: warm off-white #F5F6F8 flat canvas
Subject: exactly three distinct key tokens feed one continuous top rail into a secure vault container; the top rail visibly continues unbroken across the entire image. Below it, exactly two additional rails begin only after separate clock-shaped gates. The first lower rail visibly uses exactly two of the three key tokens. The later lower rail visibly uses exactly one of the three key tokens. All three rails end at the same secure vault container. The lower rails are additions, never replacements.
Style/medium: minimal flat vector-like illustration; crisp geometric construction; bold uniform slate outlines that remain clear at 160 by 107 pixels; rounded forms; flat fills; no gradients or photographic shadows
Composition/framing: 3:2 landscape; clean left-to-right flow; exactly three key tokens grouped at left, two clock gates in the middle, vault container at right; 10 percent safe margin; no cropped objects
Color palette: warm off-white #F5F6F8 canvas, Bitcoin orange #F7931A used only to highlight unlocked routes, slate #626A73 outlines, pale gray secondary fills; maximum four colors
Text: none
Constraints: exact object counts are mandatory: three key tokens total, one continuous immediate rail, two additional delayed rails, two clock gates, one vault container. No text, letters, numbers, logos, Bitcoin symbol, currency signs, people, coins, photorealism, fake UI, QR codes, visible watermark, gradients, decorative clutter, broken top rail, or automatic motion
Output intent: a calm and precise security diagram, readable when reduced to 160 by 107 pixels
```

### `access-timeline` corrective edit

Input image: initial candidate A.

```text
Use case: precise-object-edit
Asset type: compact in-product teaching panel for the Bitcoin Core Recovery Vault desktop UI
Input images: Image 1 is the edit target and style source
Primary request: correct only the authority-count communication while retaining the same minimal flat vector style, colors, stroke weight, 3:2 canvas, safe margins, and left-to-right layout
Required composition: keep exactly three key tokens total at the left and exactly one vault container at the right. Give each key a distinct small origin node. The continuous top rail must visibly receive all three origins and remain unbroken across the full timeline. A first lower rail must begin only after the first clock gate and visibly receive branches from exactly two of the three origins. A second lower rail must begin only after a later second clock gate and visibly receive a branch from exactly one of the three origins. Use clean connector junctions so a viewer can count three, then two, then one without any labels. All three rails terminate at the same vault. The lower rails are additional paths, not replacements.
Constraints: exact counts are mandatory: three key tokens total, three key-origin connectors into the continuous top rail, two connectors into the first delayed rail, one connector into the later delayed rail, two clock gates total, one vault total. Remove any ambiguous blob-like junctions. No extra keys, no text, letters, numbers, logos, Bitcoin symbol, currency signs, people, coins, fake UI, QR codes, gradients, visible watermark, or decorative objects.
```

### `recovery-kit` initial candidates

Input image: selected `access-timeline-c`, style reference only.

```text
Use case: infographic-diagram
Asset type: compact in-product teaching panel for the Bitcoin Core Recovery Vault desktop UI
Input images: Image 1 is a style-only reference for palette, flat vector treatment, outline weight, corner language, and visual density. Do not copy its keys, clocks, rails, or vault composition.
Primary request: show one complete Recovery Kit being printed and moved into offline physical storage
Scene/backdrop: warm off-white #F5F6F8 flat canvas
Subject: at left, one simple desktop printer outputs an organized kit. The kit contains exactly one public-policy booklet with abstract non-readable lines and exactly three separate sealed recovery slips. At right, one open archival document box or small physical safe receives the complete bundled kit. Use one clear directional arrow from printer to storage. Keep the booklet and all three slips visibly countable and grouped as one kit.
Style/medium: minimal flat vector-like illustration matching Image 1; crisp geometry; bold uniform slate outlines; rounded forms; flat fills; no gradients or photographic shadows
Composition/framing: 3:2 landscape; printer left, complete kit centered, offline storage right; 10 percent safe margin; no cropped objects; readable at 160 by 107 pixels
Color palette: warm off-white #F5F6F8 canvas, Bitcoin orange #F7931A used only for the complete-kit path and small seals, slate #626A73 outlines, pale gray secondary fills; maximum four colors
Text: none
Constraints: exact counts are mandatory: one printer, one public-policy booklet, three sealed recovery slips, one offline storage container. No cloud, network, Wi-Fi, phone, computer screen, extra papers, text, letters, numbers, logos, Bitcoin symbol, currency signs, people, coins, QR codes, fake UI, photorealism, visible watermark, gradients, or decorative clutter.
```

### `recovery-kit` corrective edit

Input image: initial candidate B.

```text
Use case: precise-object-edit
Asset type: compact in-product teaching panel for the Bitcoin Core Recovery Vault desktop UI
Input images: Image 1 is the edit target and style source
Primary request: keep the same minimal flat vector style and left-to-right printer-to-offline-storage story, but show the kit exactly once and make its contents countable
Required composition: one printer at left with an empty output tray; one complete Recovery Kit centered between printer and storage, consisting of exactly one public-policy booklet with abstract lines and exactly three separate sealed recovery slips; one simple open archival document box at right, empty and ready to receive the kit; one orange directional arrow running behind or beneath the centered kit toward the box. The centered booklet and three slips are the only papers in the entire image.
Constraints: exact global counts are mandatory: one printer, one booklet, three sealed slips, one empty offline storage box, one arrow. Remove duplicate papers from the printer and box. Remove keypad, key icon, text, letters, numbers, logos, QR codes, cloud, phone, Wi-Fi, people, coins, gradients, visible watermark, and decorative objects. Preserve the 3:2 canvas, #F5F6F8 background, #F7931A accent, slate outlines, stroke weight, safe margin, and visual density.
```

### `address-verification` initial candidates

Input image: selected `access-timeline-c`, style reference only.

```text
Use case: infographic-diagram
Asset type: compact in-product teaching panel for the Bitcoin Core Recovery Vault desktop UI
Input images: Image 1 is a style-only reference for palette, flat vector treatment, outline weight, corner language, and visual density. Do not copy its keys, clocks, rails, or vault composition.
Primary request: visualize independent comparison of one receive address across three separate sources that agree
Scene/backdrop: warm off-white #F5F6F8 flat canvas
Subject: three clearly separate objects arranged in a triangle: one desktop address card with two abstract horizontal address lines, one hardware-wallet device with the same two abstract line lengths on its display, and one printed public-policy card with the same line pattern. Thin comparison connectors meet at one central orange check mark to show agreement. The three objects remain physically separate to communicate independent verification.
Style/medium: minimal flat vector-like illustration matching Image 1; crisp geometry; bold uniform slate outlines; rounded forms; flat fills; no gradients or photographic shadows
Composition/framing: 3:2 landscape; three-source triangular comparison; central check mark; 10 percent safe margin; no cropped objects; readable at 160 by 107 pixels
Color palette: warm off-white #F5F6F8 canvas, Bitcoin orange #F7931A used only for the agreement mark and connectors, slate #626A73 outlines, pale gray secondary fills; maximum four colors
Text: none
Constraints: exactly one address card, one hardware-wallet device, one printed policy card, and one check mark. Abstract line patterns only. No QR-like grid, QR finder squares, readable address, text, letters, numbers, logos, Bitcoin symbol, currency signs, people, coins, key icons, fake UI, photorealism, visible watermark, gradients, or decorative clutter.
```

### `restore-authority` initial candidates

Input image: selected `access-timeline-c`, style reference only.

```text
Use case: infographic-diagram
Asset type: compact in-product teaching panel for the Bitcoin Core Recovery Vault desktop UI
Input images: Image 1 is a style-only reference for palette, flat vector treatment, outline weight, corner language, and visual density. Do not copy its keys, clocks, rails, or vault composition.
Primary request: explain that a public policy restores a watch-only view while either recovered phrases or exact hardware can separately add signing authority
Scene/backdrop: warm off-white #F5F6F8 flat canvas
Subject: one public-policy booklet at left feeds a clean outline-only vault view in the center. From the center, two clearly separate optional lower branches approach without merging with each other: the upper optional branch contains a tidy bundle of exactly three sealed recovery slips; the lower optional branch contains one hardware-wallet device. Each optional branch adds one small solid key token beside the outline vault, communicating added signing authority. The branches must look like alternatives, not cumulative requirements.
Style/medium: minimal flat vector-like illustration matching Image 1; crisp geometry; bold uniform slate outlines; rounded forms; flat fills; no gradients or photographic shadows
Composition/framing: 3:2 landscape; policy left, outline vault center, two separated authority alternatives right; 10 percent safe margin; no cropped objects; readable at 160 by 107 pixels
Color palette: warm off-white #F5F6F8 canvas, Bitcoin orange #F7931A used only for optional authority connectors and solid key tokens, slate #626A73 outlines, pale gray secondary fills; maximum four colors
Text: none
Constraints: exact counts are mandatory: one policy booklet, one outline vault view, three sealed slips on one branch, one hardware wallet on the other branch, two small authority key tokens total. No branch merging, plus signs, checkboxes, radio buttons, arrows that imply all inputs are required, extra devices, text, letters, numbers, logos, Bitcoin symbol, currency signs, people, coins, QR codes, fake UI, photorealism, visible watermark, gradients, or decorative clutter.
```

### `delayed-recovery` initial candidates

Input image: selected `access-timeline-c`, style reference only.

```text
Use case: infographic-diagram
Asset type: compact in-product teaching panel for the Bitcoin Core Recovery Vault desktop UI
Input images: Image 1 is a style-only reference for palette, flat vector treatment, outline weight, corner language, and visual density. Do not copy its composition.
Primary request: show an explicit delayed recovery spend after one unavailable key blocks the immediate three-key route
Scene/backdrop: warm off-white #F5F6F8 flat canvas
Subject: exactly three key tokens at left. One token is muted and separated by a small break, visibly unavailable. The immediate top route from all three keys stops at a clear pause barrier. A distinct lower route remains inactive before one clock gate, then turns orange after the gate. Exactly two available key tokens visibly authorize this lower route. After the gate, one small group of eligible coin-like plain discs moves by a deliberate transaction arrow into one newly secured vault container at right. Nothing moves before the clock gate.
Style/medium: minimal flat vector-like illustration matching Image 1; crisp geometry; bold uniform slate outlines; rounded forms; flat fills; no gradients or photographic shadows
Composition/framing: 3:2 landscape; keys and blocked top route left, clock gate center, explicit lower transaction route to fresh vault right; 10 percent safe margin; no cropped objects; readable at 160 by 107 pixels
Color palette: warm off-white #F5F6F8 canvas, Bitcoin orange #F7931A only after the clock gate and on the deliberate transaction arrow, slate #626A73 outlines, pale gray secondary fills; maximum four colors
Text: none
Constraints: exactly three key tokens total, exactly one visibly unavailable, exactly two available keys connected to the delayed route, one clock gate, one paused immediate route, one fresh vault. No automatic motion, no orange route before the gate, no extra keys, no padlock that implies permanent loss, no text, letters, numbers, logos, Bitcoin symbol, currency signs, people, QR codes, fake UI, photorealism, visible watermark, gradients, or decorative clutter.
```

### `delayed-recovery` corrective edit

Input image: initial candidate B.

```text
Use case: precise-object-edit
Asset type: compact in-product teaching panel for the Bitcoin Core Recovery Vault desktop UI
Input images: Image 1 is the edit target and style source
Primary request: preserve the clean blocked-top-route, clock-gated lower route, orange transaction arrow, coin discs, and fresh vault, while correcting the key count
Required composition: show exactly three key tokens total, grouped once at upper left. Within that group, one key is muted and visibly unavailable; the other two remain active. Remove the separate ghost key below the group. Draw two clean origin branches from the two active keys into the lower delayed route before the clock. The blocked immediate route still receives all three origins and ends at the pause barrier. Nothing else changes.
Constraints: exact global counts are mandatory: three keys total with one unavailable and two active, one pause barrier, one clock gate, one delayed route, one group of plain coin discs, one fresh vault. No extra keys or key silhouettes. Preserve every other object, path direction, 3:2 crop, #F5F6F8 canvas, #F7931A accent, slate outlines, stroke weight, safe margin, and flat vector style. No text, letters, numbers, logos, Bitcoin symbol, currency signs, people, QR codes, fake UI, gradients, or visible watermark.
```

### `protection-renewal` initial candidates

Input image: selected `access-timeline-c`, style reference only.

```text
Use case: infographic-diagram
Asset type: compact in-product teaching panel for the Bitcoin Core Recovery Vault desktop UI
Input images: Image 1 is a style-only reference for palette, flat vector treatment, outline weight, corner language, and visual density. Do not copy its composition.
Primary request: visualize a three-key self-transfer that moves separate privacy groups to fresh vault outputs and restarts their clocks only after transfer
Scene/backdrop: warm off-white #F5F6F8 flat canvas
Subject: exactly two separate groups of plain coin-like discs at left, each beside its own older clock. Keep a visible gap between the groups. Exactly three key tokens jointly authorize two separate parallel orange transfer arrows. The arrows never merge. Each arrow leads to its own fresh vault-output tile at right, each beside its own new clock with hands reset to the start. Show a small confirmation node immediately before each new clock so reset happens after transfer, not before.
Style/medium: minimal flat vector-like illustration matching Image 1; crisp geometry; bold uniform slate outlines; rounded forms; flat fills; no gradients or photographic shadows
Composition/framing: 3:2 landscape; two separate old groups left, three-key authorization centered, two separate fresh outputs and new clocks right; 10 percent safe margin; no cropped objects; readable at 160 by 107 pixels
Color palette: warm off-white #F5F6F8 canvas, Bitcoin orange #F7931A for the two authorized transfer arrows and reset markers, slate #626A73 outlines, pale gray secondary fills; maximum four colors
Text: none
Constraints: exact counts are mandatory: two separate groups, two old clocks, three key tokens, two non-merging arrows, two fresh output tiles, two new clocks, two confirmation nodes. Never merge the groups. No recycle logo, circular loop suggesting endless automation, extra keys, text, letters, numbers, logos, Bitcoin symbol, currency signs, people, QR codes, fake UI, photorealism, visible watermark, gradients, or decorative clutter.
```

### `vault-ready` initial candidates

Input image: selected `access-timeline-c`, style reference only.

```text
Use case: infographic-diagram
Asset type: compact in-product teaching panel for the Bitcoin Core Recovery Vault desktop UI
Input images: Image 1 is a style-only reference for palette, flat vector treatment, outline weight, corner language, and visual density. Do not copy its composition.
Primary request: show a newly verified Recovery Vault ready to receive one small test payment
Scene/backdrop: warm off-white #F5F6F8 flat canvas
Subject: one modest shielded vault container at right receives exactly one small plain test-payment disc along one short orange arrow. Behind and clearly secondary, one closed offline Recovery Kit box and one hardware-wallet device each carry a small matching check mark, showing setup evidence rather than additional spending inputs. Keep the single test disc visually small relative to the vault and do not show a pile or main balance.
Style/medium: minimal flat vector-like illustration matching Image 1; crisp geometry; bold uniform slate outlines; rounded forms; flat fills; no gradients or photographic shadows
Composition/framing: 3:2 landscape; small test disc left, verified supporting artifacts centered/back, shielded vault right; 10 percent safe margin; no cropped objects; readable at 160 by 107 pixels
Color palette: warm off-white #F5F6F8 canvas, Bitcoin orange #F7931A only for the test-payment arrow and verification marks, slate #626A73 outlines, pale gray secondary fills; maximum four colors
Text: none
Constraints: exactly one test-payment disc, one vault, one Recovery Kit box, one hardware wallet, two small check marks. No pile of coins, large balance, extra keys, text, letters, numbers, logos, Bitcoin symbol, currency signs, people, QR codes, fake UI, photorealism, visible watermark, gradients, confetti, or decorative clutter.
```

### Dark palette edits

Input image: the applicable selected light master.

```text
Use case: precise-object-edit
Asset type: dark-theme counterpart for a compact Bitcoin Core Recovery Vault teaching panel
Input images: Image 1 is the edit target
Primary request: palette-only edit of Image 1 for a dark Qt desktop theme
Color palette: replace the light canvas with uniform #24262A; use #D6DADE for primary outlines; use #858C94 and #383B40 for secondary fills; retain #F7931A as the only accent
Constraints: preserve every object, exact object count, semantic relationship, connector path, clock hand, check mark, position, crop, spacing, line weight, and security meaning from Image 1 as closely as possible. Do not add, remove, move, reinterpret, mirror, crop, or relabel anything. Preserve the 3:2 composition and safe margins. No text, letters, numbers, logos, Bitcoin symbol, currency signs, people, QR codes, gradients, new shadows, visible watermark, or decorative elements. The result must remain clear when reduced to 160 by 107 pixels.
```
