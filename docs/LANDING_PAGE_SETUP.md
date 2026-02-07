# Simple Landing Page Setup with GitHub Pages

This is the **boring, simple, founder-efficient** approach to having a landing page.

## Why This Approach?

- **Zero cost** - Free GitHub Pages hosting
- **Zero maintenance** - Static HTML, no build step
- **Zero complexity** - One file, instant deploy
- **Fully acceptable** - Devs don't expect fancy marketing sites

## Setup (5 minutes)

### 1. Enable GitHub Pages

In your repository settings:
1. Go to Settings → Pages
2. Source: Deploy from a branch
3. Branch: `main` (or `master`)
4. Folder: `/docs`
5. Save

### 2. Your landing page is ready

The file `docs/index.html` is already created. GitHub will automatically serve it at:

```
https://<your-username>.github.io/rukn/
```

### 3. (Optional) Use a custom domain

If you own `rukn.dev`:

1. Add a file `docs/CNAME` with content:
   ```
   rukn.dev
   ```

2. Configure DNS:
   - Add a CNAME record pointing `rukn.dev` to `<your-username>.github.io`
   - Or A records to GitHub's IPs (see [GitHub docs](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site))

3. Wait 24 hours for DNS propagation

4. Your landing page is now at `https://rukn.dev`

## What NOT to do

❌ Don't add a build step (React, Next.js, etc.)  
❌ Don't add analytics, forms, or CRMs  
❌ Don't overthink the design  
❌ Don't delay shipping because "it's not perfect"  

## What to do when ready to take payments

When you're ready to accept Pro subscriptions:

1. Set up [Stripe](https://stripe.com) or [Paddle](https://paddle.com)
2. Add a "Get Pro" button that links to your payment page
3. After payment, email the license key (or automate it with Zapier/Make)
4. That's it

No need for:
- Hosted billing portal (Stripe has one)
- User database (licenses are local files)
- Login system (it's a CLI tool)
- Dashboard (not needed for CLI)

## The Complete Sales Flow

1. User tries Free tier → likes it
2. User hits a Pro feature → sees value message
3. User clicks "Get Pro" link → goes to your landing page
4. User clicks "Get Pro" → goes to Stripe checkout
5. User pays → receives license key via email
6. User runs `rukn license set <key>` → unlocked
7. User is happy → tells their team

This is **founder-friendly** because:
- No customer support (self-service)
- No onboarding calls
- No manual license delivery (automate with Stripe webhooks)
- No SaaS infrastructure

## When to upgrade from this

You should build something more complex **only when**:

- You're doing $10k+/month in revenue
- OR you have enterprise customers asking for SSO/SAML
- OR you want team features (shared baselines, etc.)

Until then, this is perfect.

## Example URLs in the CLI

With this setup, your CLI can safely reference:

```bash
# These all work
https://github.com/cWashington91/rukn#pricing          # Always works
https://<your-username>.github.io/rukn/#pricing        # After Pages enabled
https://rukn.dev/#pricing                              # After custom domain
```

The GitHub URL always works as a fallback.

## Updating the landing page

Just edit `docs/index.html` and push to GitHub. Changes go live in ~1 minute.

No build. No deploy step. No complexity.

## Summary

This is the **right amount of marketing infrastructure** for a CLI-first dev tool:

- Static HTML landing page
- GitHub Pages hosting (free)
- Stripe for payments (when ready)
- GitHub Issues for support
- README for docs

Everything else is distraction at this stage.
