"use client";

import { useState } from "react";
import { Button } from "@/components/ui/Button";
import { ShieldCheckIcon, MenuIcon, XIcon } from "@/components/landing/icons";

const NAV_LINKS = [
  { label: "Product", href: "#features" },
  { label: "Compliance", href: "#compliance" },
  { label: "Pricing", href: "#cta" },
];

const TRUST_BADGES = [
  "GDPR Compliant",
  "NIS2 Ready",
  "EU Data Residency",
  "mTLS Secured",
  "Immutable Audit",
];

const TERMINAL_LINES = [
  { text: "> CISA KEV signal received: CVE-2025-21298", color: "text-accent-red" },
  { text: "> Fleet scan: 847 endpoints affected", color: "text-accent-amber" },
  { text: "> Urgency score: 94/100 (KEV + EPSS 0.97)", color: "text-accent-amber" },
  { text: "> Ring deployment: Canary (3) \u2192 Pilot (85) \u2192 Broad (759)", color: "text-accent" },
  { text: "> Canary: 3/3 verified \u2713", color: "text-accent-green" },
  { text: "> Pilot: 85/85 verified \u2713", color: "text-accent-green" },
  { text: "> Broad: 759/759 verified \u2713", color: "text-accent-green" },
  { text: "> MTTRem: 1h 47m", color: "text-accent-bright" },
];

export function Hero() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <>
      {/* Navigation */}
      <header className="fixed top-0 left-0 right-0 z-50 bg-bg-primary/80 backdrop-blur-md border-b border-border">
        <nav className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 flex items-center justify-between h-16">
          <a href="/" className="flex items-center gap-2 text-text-primary font-bold text-lg">
            <ShieldCheckIcon className="w-6 h-6 text-accent" />
            PatchPilot
          </a>

          {/* Desktop nav */}
          <div className="hidden md:flex items-center gap-8">
            {NAV_LINKS.map((link) => (
              <a
                key={link.label}
                href={link.href}
                className="text-text-secondary hover:text-text-primary text-sm transition-colors"
              >
                {link.label}
              </a>
            ))}
            <Button href="#cta" size="sm">
              Book a Demo
            </Button>
          </div>

          {/* Mobile toggle */}
          <button
            className="md:hidden text-text-secondary hover:text-text-primary"
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label="Toggle menu"
          >
            {mobileOpen ? <XIcon className="w-6 h-6" /> : <MenuIcon className="w-6 h-6" />}
          </button>
        </nav>

        {/* Mobile menu */}
        {mobileOpen && (
          <div className="md:hidden border-t border-border bg-bg-primary/95 backdrop-blur-md px-4 py-4 space-y-3">
            {NAV_LINKS.map((link) => (
              <a
                key={link.label}
                href={link.href}
                className="block text-text-secondary hover:text-text-primary text-sm py-2"
                onClick={() => setMobileOpen(false)}
              >
                {link.label}
              </a>
            ))}
            <Button href="#cta" size="sm" className="w-full">
              Book a Demo
            </Button>
          </div>
        )}
      </header>

      {/* Hero Section */}
      <section className="relative min-h-screen flex items-center hero-grid-bg pt-16">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-20 lg:py-32 w-full">
          <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
            {/* Left: Copy */}
            <div className="space-y-8">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent/30 bg-accent/5 text-accent text-xs font-medium tracking-wide uppercase">
                Exploit-to-Remediation Automation
              </div>

              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold leading-tight tracking-tight">
                From KEV Alert to{" "}
                <span className="gradient-text">Verified Patch</span>{" "}
                in Under 2 Hours
              </h1>

              <p className="text-lg text-text-secondary leading-relaxed max-w-xl">
                PatchPilot closes the gap between exploitation signal and confirmed
                remediation across your entire Windows fleet. Append-only audit trail.
                GDPR and NIS2 compliant. No black boxes.
              </p>

              <div className="flex flex-col sm:flex-row gap-4">
                <Button href="#cta" size="lg" showArrow>
                  Book a Demo
                </Button>
                <Button href="#loop" variant="secondary" size="lg">
                  See How It Works
                </Button>
              </div>

              {/* Trust badges */}
              <div className="flex flex-wrap gap-3 pt-2">
                {TRUST_BADGES.map((badge) => (
                  <span
                    key={badge}
                    className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-bg-secondary border border-border text-text-muted text-xs"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-accent-green" />
                    {badge}
                  </span>
                ))}
              </div>
            </div>

            {/* Right: Terminal visualization */}
            <div className="hidden lg:block">
              <div className="glow-card p-6 animate-pulse-glow">
                <div className="flex items-center gap-2 mb-4">
                  <span className="w-3 h-3 rounded-full bg-accent-red/60" />
                  <span className="w-3 h-3 rounded-full bg-accent-amber/60" />
                  <span className="w-3 h-3 rounded-full bg-accent-green/60" />
                  <span className="ml-3 text-text-muted text-xs font-mono">patchpilot-console</span>
                </div>
                <div className="space-y-2.5 font-mono text-sm">
                  {TERMINAL_LINES.map((line, i) => (
                    <div
                      key={i}
                      className={`terminal-line ${line.color}`}
                      style={{ animationDelay: `${i * 0.3}s` }}
                    >
                      {line.text}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
