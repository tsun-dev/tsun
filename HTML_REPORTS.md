# HTML Report Generation

## Overview

Tsun now generates beautiful, interactive HTML security scan reports with professional styling and comprehensive vulnerability details.

## Features

### Responsive Design
- **Mobile-friendly**: Works perfectly on desktop, tablet, and mobile devices
- **Professional styling**: Modern gradient design with intuitive color coding
- **Smooth interactions**: Hover effects and visual feedback

### Report Sections

#### Header
- Target URL
- Scan timestamp
- Professional branding

#### Vulnerability Summary
- **Dashboard cards** showing counts by severity:
  - Critical (red)
  - High (orange)
  - Medium (yellow)
  - Low (blue)
  - Total issues
- Quick visual overview of security posture

#### Detailed Findings
Each vulnerability includes:
- **Alert title** with risk badges
- **Risk level** (Critical, High, Medium, Low)
- **Confidence level** (High, Medium, Low)
- **Description** of the vulnerability
- **Affected URL(s)**
- **Plugin ID** for reference
- **Instances table** with:
  - URI
  - HTTP method
  - Parameter (if applicable)
  - Evidence/proof

#### Color Coding
- **Critical**: Red (#f55)
- **High**: Orange (#ff6b6b)
- **Medium**: Yellow (#ffc107)
- **Low**: Blue (#17a2b8)

## Usage

### Command Line

Generate HTML report:
```bash
tsun scan --target https://example.com --mock --format html --output report.html
```

### Output

The generated HTML file is self-contained with:
- Embedded CSS (no external dependencies)
- No JavaScript required
- ~12KB per report (including styles)
- Optimized for printing

## Technical Details

### Built with Maud
- **Type-safe HTML DSL** in Rust
- Compile-time HTML validation
- Zero runtime overhead
- No template files needed

### CSS Features
- CSS Grid for responsive layouts
- Flexbox for component alignment
- Media queries for mobile optimization
- CSS custom properties ready for future themes

### Browser Support
- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Mobile browsers

## Examples

### Summary Section
```
┌─────────────────────────────────────────┐
│ Vulnerability Summary                   │
├─────────────────────────────────────────┤
│ [0 Critical]  [3 High]  [2 Medium] [1 Low]  [6 Total] │
└─────────────────────────────────────────┘
```

### Vulnerability Card
```
┌─────────────────────────────────────────┐
│ [HIGH] Cookie without Secure Flag       │
│        Confidence: High                  │
├─────────────────────────────────────────┤
│ A cookie has been set without the       │
│ Secure flag...                          │
│                                         │
│ Affected URL: https://example.com/login │
│ Plugin ID: 10010                        │
│ Method: POST                            │
│ Parameter: session_id                   │
└─────────────────────────────────────────┘
```

## Report Generation Flow

```
Scanner runs
    ↓
Collects alerts from ZAP
    ↓
ScanReport::save() with format="html"
    ↓
html::generate_html_report()
    ↓
Returns HTML string with all styling
    ↓
Written to file
    ↓
Beautiful report ready for sharing
```

## Size Comparison

For a typical scan with 6 vulnerabilities:
- **HTML**: ~12 KB (includes all CSS)
- **JSON**: ~3.6 KB (structured data)
- **YAML**: ~2.6 KB (human-readable)

## Next Steps

- [ ] Export individual vulnerability remediation guidance
- [ ] Add trend charts (scans over time)
- [ ] Implement Dark mode toggle
- [ ] Add report filtering/searching in HTML
- [ ] Generate PDF from HTML reports
