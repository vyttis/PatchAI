"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/Button";
import {
  ShieldCheckIcon,
  LockIcon,
  GlobeEuropeIcon,
  DocumentIcon,
  RadarIcon,
  ServerIcon,
  ClockIcon,
  ChartIcon,
  AlertTriangleIcon,
  RocketIcon,
  CheckCircleIcon,
  XCircleIcon,
} from "@/components/landing/icons";

/* -------------------------------------------------------------------------- */
/*  AnimateOnScroll — lightweight scroll-triggered fade-in                     */
/* -------------------------------------------------------------------------- */

function AnimateOnScroll({
  children,
  className = "",
  delay = 0,
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.1 }
    );
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  return (
    <div
      ref={ref}
      className={`transition-all duration-700 ${
        visible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-6"
      } ${className}`}
      style={{ transitionDelay: `${delay}ms` }}
    >
      {children}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  TrustBar                                                                  */
/* -------------------------------------------------------------------------- */

const BADGES = [
  { label: "GDPR Compliant", icon: LockIcon },
  { label: "NIS2 Ready", icon: DocumentIcon },
  { label: "EU Data Residency", icon: GlobeEuropeIcon },
  { label: "Immutable Audit Log", icon: ShieldCheckIcon },
  { label: "mTLS Device Auth", icon: LockIcon },
];

export function TrustBar() {
  return (
    <section className="py-10 bg-bg-secondary border-y border-border">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <p className="text-center text-text-muted text-sm mb-6">
          Built for EU compliance from day one
        </p>
        <div className="flex flex-wrap justify-center gap-4 lg:gap-8">
          {BADGES.map(({ label, icon: Icon }) => (
            <div
              key={label}
              className="flex items-center gap-2 px-4 py-2 rounded-lg border border-border bg-bg-primary/50 text-text-secondary text-sm"
            >
              <Icon className="w-4 h-4 text-accent" />
              {label}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/*  ProblemSolution                                                           */
/* -------------------------------------------------------------------------- */

const PROBLEMS = [
  {
    title: "Blind Spots",
    desc: "You find out about exploited vulnerabilities from news articles, not your tools. KEV entries sit unactioned for days.",
  },
  {
    title: "Spray and Pray",
    desc: "Patches deploy fleet-wide with no canary testing. One bad update takes down 2,000 machines on a Friday afternoon.",
  },
  {
    title: "Compliance Theater",
    desc: "Your audit evidence is a spreadsheet someone updated last quarter. Auditors ask for MTTRem and you guess.",
  },
  {
    title: "Tool Gap",
    desc: "Too many endpoints for Intune-only hygiene. Not enough budget for Tanium or BigFix. You are stuck in the middle.",
  },
];

const SOLUTIONS = [
  {
    title: "Real-Time Signals",
    desc: "KEV, MSRC, EPSS, NVD, and GHSA feeds ingested automatically. Fleet exposure checks fire within minutes of a new KEV entry.",
  },
  {
    title: "Ring Rollout",
    desc: "Canary (3 devices) then pilot (10%) then broad. Auto-halt on failure or telemetry anomalies. No fleet-wide gambles.",
  },
  {
    title: "Evidence by Default",
    desc: "Append-only audit log enforced at the database level. MTTRem computed automatically. Export-ready for NIS2 and GDPR auditors.",
  },
  {
    title: "Right-Sized for You",
    desc: "Built for 500 to 5,000 endpoint fleets. EU-hosted SaaS. No six-figure contracts, no 18-month deployments.",
  },
];

export function ProblemSolution() {
  return (
    <section className="py-24 lg:py-32 bg-bg-primary">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid lg:grid-cols-2 gap-16">
          {/* Problems */}
          <div>
            <AnimateOnScroll>
              <p className="text-accent-red text-sm font-semibold tracking-widest uppercase mb-3">
                The Problem
              </p>
              <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-8">
                Patch Management Is Broken
              </h2>
            </AnimateOnScroll>
            <div className="space-y-6">
              {PROBLEMS.map((p, i) => (
                <AnimateOnScroll key={p.title} delay={i * 100}>
                  <div className="flex gap-4 p-4 rounded-xl border border-accent-red/10 bg-accent-red/5">
                    <XCircleIcon className="w-6 h-6 text-accent-red shrink-0 mt-0.5" />
                    <div>
                      <h3 className="text-text-primary font-semibold mb-1">{p.title}</h3>
                      <p className="text-text-secondary text-sm leading-relaxed">{p.desc}</p>
                    </div>
                  </div>
                </AnimateOnScroll>
              ))}
            </div>
          </div>

          {/* Solutions */}
          <div>
            <AnimateOnScroll>
              <p className="text-accent-green text-sm font-semibold tracking-widest uppercase mb-3">
                The Solution
              </p>
              <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-8">
                PatchPilot Closes the Loop
              </h2>
            </AnimateOnScroll>
            <div className="space-y-6">
              {SOLUTIONS.map((s, i) => (
                <AnimateOnScroll key={s.title} delay={i * 100}>
                  <div className="flex gap-4 p-4 rounded-xl border border-accent-green/10 bg-accent-green/5">
                    <CheckCircleIcon className="w-6 h-6 text-accent-green shrink-0 mt-0.5" />
                    <div>
                      <h3 className="text-text-primary font-semibold mb-1">{s.title}</h3>
                      <p className="text-text-secondary text-sm leading-relaxed">{s.desc}</p>
                    </div>
                  </div>
                </AnimateOnScroll>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/*  MetricsStats                                                              */
/* -------------------------------------------------------------------------- */

const METRICS = [
  { value: "<2h", label: "KEV Critical + Auto-Deploy", sub: "Exploited-in-the-wild, automated policy" },
  { value: "<24h", label: "KEV + Approval Gate", sub: "Exploited vulnerability, human sign-off" },
  { value: "<72h", label: "Non-KEV High Severity", sub: "CVSS 7.0+ with elevated EPSS" },
  { value: "<14d", label: "Standard Patches", sub: "Routine updates via ring rollout" },
];

export function MetricsStats() {
  return (
    <section className="py-24 lg:py-32 bg-bg-secondary">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <AnimateOnScroll className="text-center max-w-3xl mx-auto mb-16">
          <p className="text-accent text-sm font-semibold tracking-widest uppercase mb-3">
            Mean Time to Remediation
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
            The Only KPI That Matters
          </h2>
          <p className="text-text-secondary text-lg">
            MTTRem measures from when PatchPilot ingested the exploitation signal to when the
            patch was verified on the endpoint. Not &ldquo;deployed.&rdquo; Verified.
          </p>
        </AnimateOnScroll>

        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {METRICS.map((m, i) => (
            <AnimateOnScroll key={m.label} delay={i * 100}>
              <div className="glow-card p-6 text-center">
                <div className="text-4xl sm:text-5xl font-bold font-mono gradient-text mb-2">
                  {m.value}
                </div>
                <div className="text-text-primary font-semibold text-sm mb-1">{m.label}</div>
                <div className="text-text-muted text-xs">{m.sub}</div>
              </div>
            </AnimateOnScroll>
          ))}
        </div>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/*  FeaturesGrid                                                              */
/* -------------------------------------------------------------------------- */

const FEATURES = [
  {
    icon: RadarIcon,
    title: "Intel Pipeline",
    tagline: "Five feeds. One truth.",
    bullets: [
      "CISA KEV, MSRC, EPSS, NVD, and GHSA \u2014 parsed and stored with raw blob provenance",
      "MSRC resilience: exponential backoff, Retry-After, 2h cache, 12h staleness alerting",
      "Parser contract tests pin expected schemas \u2014 schema drift never silently breaks matching",
    ],
  },
  {
    icon: ServerIcon,
    title: "Fleet Matching",
    tagline: "Your actual attack surface.",
    bullets: [
      "Dual-method KB collection (WUA + registry/DISM) with cache fallback",
      "Normalized software inventory with delta check-ins",
      "PatchPilot knows what is installed, not what should be",
    ],
  },
  {
    icon: RocketIcon,
    title: "Ring Rollout",
    tagline: "Deploy with confidence. Halt on evidence.",
    bullets: [
      "Canary, pilot, broad with configurable thresholds",
      "Before/after telemetry: CPU, crash events, reboots, disk",
      "Auto-halt when canary failure exceeds 20% or anomalies breach",
    ],
  },
  {
    icon: AlertTriangleIcon,
    title: "Zero-Day Response",
    tagline: "When there is no patch, there is still a workflow.",
    bullets: [
      "UnpatchedExposure is a first-class entity with its own state machine",
      "Automated recheck loop \u2014 transitions to patched when KB appears",
      "Mitigation evidence trail for risk-accepted exposures",
    ],
  },
];

export function FeaturesGrid() {
  return (
    <section id="features" className="py-24 lg:py-32 bg-bg-primary">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <AnimateOnScroll className="text-center max-w-3xl mx-auto mb-16">
          <p className="text-accent text-sm font-semibold tracking-widest uppercase mb-3">
            Capabilities
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
            Everything Between the Alert and the Evidence
          </h2>
        </AnimateOnScroll>

        <div className="grid md:grid-cols-2 gap-6">
          {FEATURES.map((f, i) => {
            const Icon = f.icon;
            return (
              <AnimateOnScroll key={f.title} delay={i * 100}>
                <div className="glow-card p-6 lg:p-8 h-full">
                  <Icon className="w-8 h-8 text-accent mb-4" />
                  <h3 className="text-xl font-bold text-text-primary mb-1">{f.title}</h3>
                  <p className="text-accent text-sm font-medium mb-4">{f.tagline}</p>
                  <ul className="space-y-2">
                    {f.bullets.map((b) => (
                      <li key={b} className="flex gap-2 text-text-secondary text-sm">
                        <CheckCircleIcon className="w-4 h-4 text-accent-green shrink-0 mt-0.5" />
                        <span>{b}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </AnimateOnScroll>
            );
          })}
        </div>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/*  RingRolloutVisual                                                         */
/* -------------------------------------------------------------------------- */

const RINGS = [
  {
    name: "Canary",
    pct: "1%",
    detail: "or 3 devices (whichever is larger)",
    halt: ">20% failure = auto-halt",
    width: "w-1/6",
  },
  {
    name: "Pilot",
    pct: "10%",
    detail: "of total fleet",
    halt: "Requires canary pass",
    width: "w-2/6",
  },
  {
    name: "Broad",
    pct: "89%",
    detail: "remainder of fleet",
    halt: "Requires pilot pass",
    width: "w-full",
  },
];

export function RingRolloutVisual() {
  return (
    <section className="py-24 lg:py-32 bg-bg-secondary">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <AnimateOnScroll className="text-center max-w-3xl mx-auto mb-16">
          <p className="text-accent text-sm font-semibold tracking-widest uppercase mb-3">
            Safe Deployment
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
            Every Patch Earns Its Way Across Your Fleet
          </h2>
        </AnimateOnScroll>

        <div className="max-w-3xl mx-auto space-y-6">
          {RINGS.map((ring, i) => (
            <AnimateOnScroll key={ring.name} delay={i * 150}>
              <div className="glow-card p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <span className="text-accent font-bold font-mono text-lg">{ring.pct}</span>
                    <span className="text-text-primary font-semibold">{ring.name}</span>
                    <span className="text-text-muted text-sm">{ring.detail}</span>
                  </div>
                  <span className="text-text-muted text-xs border border-border rounded-md px-2 py-1">
                    {ring.halt}
                  </span>
                </div>
                <div className="h-2 bg-bg-tertiary rounded-full overflow-hidden">
                  <div
                    className={`h-full bg-gradient-to-r from-accent to-accent-violet rounded-full ${ring.width}`}
                  />
                </div>
              </div>
            </AnimateOnScroll>
          ))}
        </div>

        <AnimateOnScroll delay={500} className="max-w-3xl mx-auto mt-8">
          <div className="flex gap-4 p-5 rounded-xl border border-border bg-bg-primary/50">
            <ChartIcon className="w-6 h-6 text-accent shrink-0 mt-0.5" />
            <p className="text-text-secondary text-sm leading-relaxed">
              PatchPilot collects telemetry before and after every deployment &mdash; CPU, crash events,
              reboot count, and disk space. If the canary degrades, broad rollout never starts.
            </p>
          </div>
        </AnimateOnScroll>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/*  ComplianceSection                                                         */
/* -------------------------------------------------------------------------- */

const GDPR_ITEMS = [
  "EU data residency: Supabase, Fly.io, Upstash all in Frankfurt",
  "Right to erasure: complete org data purge within 30 days",
  "Data portability: full export as JSON/CSV",
  "AI disabled by default \u2014 opt-in requires explicit org consent",
  "Sub-processors documented: Supabase, Fly.io, Upstash, Anthropic (AI opt-in)",
  "DPA template provided before onboarding",
];

const NIS2_ITEMS = [
  "Incident tracking with auto-calculated deadlines",
  "Early warning due: detected + 24 hours",
  "Notification due: detected + 72 hours",
  "Final report due: detected + 3 months",
  "MTTRem report + audit log = Article 21 evidence",
  "Compliance evidence export for auditors",
];

export function ComplianceSection() {
  return (
    <section id="compliance" className="py-24 lg:py-32 bg-bg-primary">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <AnimateOnScroll className="text-center max-w-3xl mx-auto mb-16">
          <p className="text-accent text-sm font-semibold tracking-widest uppercase mb-3">
            Compliance
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
            GDPR and NIS2. Built In, Not Bolted On.
          </h2>
        </AnimateOnScroll>

        <div className="grid md:grid-cols-2 gap-8 max-w-5xl mx-auto">
          <AnimateOnScroll>
            <div className="glow-card p-6 lg:p-8 h-full">
              <div className="flex items-center gap-3 mb-6">
                <LockIcon className="w-6 h-6 text-accent" />
                <h3 className="text-xl font-bold text-text-primary">GDPR</h3>
              </div>
              <ul className="space-y-3">
                {GDPR_ITEMS.map((item) => (
                  <li key={item} className="flex gap-2 text-text-secondary text-sm">
                    <CheckCircleIcon className="w-4 h-4 text-accent-green shrink-0 mt-0.5" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </AnimateOnScroll>

          <AnimateOnScroll delay={100}>
            <div className="glow-card p-6 lg:p-8 h-full">
              <div className="flex items-center gap-3 mb-6">
                <DocumentIcon className="w-6 h-6 text-accent" />
                <h3 className="text-xl font-bold text-text-primary">NIS2</h3>
              </div>
              <ul className="space-y-3">
                {NIS2_ITEMS.map((item) => (
                  <li key={item} className="flex gap-2 text-text-secondary text-sm">
                    <CheckCircleIcon className="w-4 h-4 text-accent-green shrink-0 mt-0.5" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </AnimateOnScroll>
        </div>

        <AnimateOnScroll delay={200} className="max-w-5xl mx-auto mt-8">
          <div className="flex gap-4 p-5 rounded-xl border border-accent/20 bg-accent/5 text-center justify-center">
            <GlobeEuropeIcon className="w-5 h-5 text-accent shrink-0 mt-0.5" />
            <p className="text-text-secondary text-sm">
              All infrastructure runs in Frankfurt. Supabase, Fly.io, Upstash &mdash; every byte stays in the EU.
            </p>
          </div>
        </AnimateOnScroll>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/*  ComparisonTable                                                           */
/* -------------------------------------------------------------------------- */

const COMPARISON_ROWS = [
  { cap: "KEV feed auto-ingestion", intune: false, pp: true, enterprise: "Varies" },
  { cap: "Ring rollout with auto-halt", intune: false, pp: true, enterprise: true },
  { cap: "Zero-day response workflow", intune: false, pp: true, enterprise: "Partial" },
  { cap: "MTTRem tracking", intune: false, pp: true, enterprise: "Manual" },
  { cap: "NIS2 incident management", intune: false, pp: true, enterprise: "Add-on" },
  { cap: "DB-enforced audit log", intune: false, pp: true, enterprise: "Varies" },
  { cap: "EU data residency", intune: "Partial", pp: true, enterprise: "Varies" },
  { cap: "Fleet sweet spot", intune: "<500", pp: "500\u20135,000", enterprise: "5,000+" },
  { cap: "Deployment complexity", intune: "Low", pp: "Low", enterprise: "High" },
  { cap: "Annual cost", intune: "Included*", pp: "$$", enterprise: "$$$$" },
];

function CellValue({ val }: { val: boolean | string }) {
  if (val === true) return <CheckCircleIcon className="w-5 h-5 text-accent-green mx-auto" />;
  if (val === false) return <XCircleIcon className="w-5 h-5 text-accent-red/60 mx-auto" />;
  return <span className="text-text-secondary text-sm">{val}</span>;
}

export function ComparisonTable() {
  return (
    <section className="py-24 lg:py-32 bg-bg-secondary">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <AnimateOnScroll className="text-center max-w-3xl mx-auto mb-16">
          <p className="text-accent text-sm font-semibold tracking-widest uppercase mb-3">
            Why PatchPilot
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
            Built for the Gap Between Intune and Tanium
          </h2>
        </AnimateOnScroll>

        <AnimateOnScroll>
          <div className="overflow-x-auto rounded-xl border border-border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-bg-tertiary">
                  <th className="text-left text-text-secondary font-medium px-4 py-3 min-w-[200px]">
                    Capability
                  </th>
                  <th className="text-center text-text-secondary font-medium px-4 py-3 w-32">
                    Intune / WSUS
                  </th>
                  <th className="text-center font-medium px-4 py-3 w-32 bg-accent/5 text-accent border-x border-accent/20">
                    PatchPilot
                  </th>
                  <th className="text-center text-text-secondary font-medium px-4 py-3 w-32">
                    Enterprise
                  </th>
                </tr>
              </thead>
              <tbody>
                {COMPARISON_ROWS.map((row, i) => (
                  <tr
                    key={row.cap}
                    className={`border-b border-border ${i % 2 === 0 ? "bg-bg-secondary" : "bg-bg-primary/50"}`}
                  >
                    <td className="px-4 py-3 text-text-primary">{row.cap}</td>
                    <td className="px-4 py-3 text-center">
                      <CellValue val={row.intune} />
                    </td>
                    <td className="px-4 py-3 text-center bg-accent/5 border-x border-accent/10">
                      <CellValue val={row.pp} />
                    </td>
                    <td className="px-4 py-3 text-center">
                      <CellValue val={row.enterprise} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-text-muted text-xs mt-3 text-center">
            *Intune included with Microsoft 365, but patch management capabilities are limited.
          </p>
        </AnimateOnScroll>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/*  Testimonials (persona-based value props)                                  */
/* -------------------------------------------------------------------------- */

const PERSONAS = [
  {
    role: "CISO / Head of IT Security",
    icon: ShieldCheckIcon,
    quote:
      "You need MTTRem numbers for the board and NIS2 evidence for the regulator. PatchPilot computes both automatically from the same data.",
  },
  {
    role: "IT Operations Lead",
    icon: ServerIcon,
    quote:
      "You need patches deployed without breaking production. Ring rollout with telemetry-driven halt means canary catches problems before broad rollout starts.",
  },
  {
    role: "Compliance Officer",
    icon: DocumentIcon,
    quote:
      "You need an audit trail that proves what happened, when, and why. PatchPilot\u2019s append-only log is enforced at the database level, not by application code.",
  },
];

export function TestimonialSection() {
  return (
    <section className="py-24 lg:py-32 bg-bg-primary">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <AnimateOnScroll className="text-center max-w-3xl mx-auto mb-16">
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
            Built for Security Teams Who Ship Evidence, Not Excuses
          </h2>
        </AnimateOnScroll>

        <div className="grid md:grid-cols-3 gap-6">
          {PERSONAS.map((p, i) => {
            const Icon = p.icon;
            return (
              <AnimateOnScroll key={p.role} delay={i * 100}>
                <div className="glow-card p-6 h-full flex flex-col">
                  <Icon className="w-8 h-8 text-accent mb-4" />
                  <p className="text-text-secondary text-sm leading-relaxed flex-1 mb-4">
                    &ldquo;{p.quote}&rdquo;
                  </p>
                  <p className="text-text-primary text-sm font-semibold">{p.role}</p>
                </div>
              </AnimateOnScroll>
            );
          })}
        </div>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/*  FinalCTA                                                                  */
/* -------------------------------------------------------------------------- */

export function FinalCTA() {
  return (
    <section
      id="cta"
      className="py-24 lg:py-32 bg-gradient-to-br from-bg-secondary via-bg-primary to-bg-secondary"
    >
      <div className="mx-auto max-w-3xl px-4 sm:px-6 lg:px-8 text-center">
        <AnimateOnScroll>
          <ClockIcon className="w-12 h-12 text-accent mx-auto mb-6" />
          <h2 className="text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight mb-4">
            Stop Guessing.{" "}
            <span className="gradient-text">Start Remediating.</span>
          </h2>
          <p className="text-text-secondary text-lg mb-8 max-w-xl mx-auto">
            See PatchPilot close the loop from KEV alert to verified patch in a live
            demo with your fleet profile.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-6">
            <Button href="#cta" size="lg" showArrow>
              Book a Demo
            </Button>
            <Button href="mailto:hello@patchpilot.com" variant="secondary" size="lg">
              Contact Sales
            </Button>
          </div>
          <p className="text-text-muted text-sm">
            No credit card. No 6-month contract. 30-minute technical walkthrough with a security engineer.
          </p>
        </AnimateOnScroll>
      </div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */
/*  Footer                                                                    */
/* -------------------------------------------------------------------------- */

const PRODUCT_LINKS = [
  "Six-Stage Loop",
  "Ring Rollout",
  "Intel Pipeline",
  "Zero-Day Response",
  "MTTRem Analytics",
];

const COMPLIANCE_LINKS = [
  "GDPR",
  "NIS2",
  "Data Residency",
  "Audit Log",
  "DPA Template",
];

const COMPANY_LINKS = [
  "About",
  "Contact",
  "Privacy Policy",
  "Terms of Service",
  "Impressum",
];

export function Footer() {
  return (
    <footer className="border-t border-border bg-bg-secondary py-16">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-10 mb-12">
          {/* Brand */}
          <div>
            <div className="flex items-center gap-2 text-text-primary font-bold text-lg mb-3">
              <ShieldCheckIcon className="w-5 h-5 text-accent" />
              PatchPilot
            </div>
            <p className="text-text-secondary text-sm leading-relaxed">
              Exploit-to-Remediation Automation Platform. EU-hosted. GDPR compliant. NIS2 ready.
            </p>
          </div>

          {/* Product */}
          <div>
            <h4 className="text-text-primary font-semibold text-sm mb-4">Product</h4>
            <ul className="space-y-2">
              {PRODUCT_LINKS.map((link) => (
                <li key={link}>
                  <a href="#features" className="text-text-secondary hover:text-text-primary text-sm transition-colors">
                    {link}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Compliance */}
          <div>
            <h4 className="text-text-primary font-semibold text-sm mb-4">Compliance</h4>
            <ul className="space-y-2">
              {COMPLIANCE_LINKS.map((link) => (
                <li key={link}>
                  <a href="#compliance" className="text-text-secondary hover:text-text-primary text-sm transition-colors">
                    {link}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Company */}
          <div>
            <h4 className="text-text-primary font-semibold text-sm mb-4">Company</h4>
            <ul className="space-y-2">
              {COMPANY_LINKS.map((link) => (
                <li key={link}>
                  <a href="#" className="text-text-secondary hover:text-text-primary text-sm transition-colors">
                    {link}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="border-t border-border pt-8 flex flex-col sm:flex-row justify-between items-center gap-4">
          <p className="text-text-muted text-xs">
            &copy; 2024&ndash;2026 PatchPilot GmbH. All rights reserved.
          </p>
          <p className="text-text-muted text-xs">
            All infrastructure hosted in Frankfurt, Germany.
          </p>
        </div>
      </div>
    </footer>
  );
}
