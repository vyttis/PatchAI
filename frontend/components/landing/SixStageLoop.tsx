"use client";

import { useEffect, useRef, useState } from "react";
import {
  RadarIcon,
  CrosshairIcon,
  ScaleIcon,
  RocketIcon,
  ShieldCheckIcon,
  DocumentIcon,
} from "@/components/landing/icons";

const STAGES = [
  {
    num: "01",
    name: "Signal",
    icon: RadarIcon,
    color: "text-accent-red",
    borderColor: "border-accent-red/30",
    bgColor: "bg-accent-red/5",
    desc: "Real-time ingestion from CISA KEV, MSRC, EPSS, NVD, and GHSA feeds. KEV entries trigger immediate fleet checks.",
  },
  {
    num: "02",
    name: "Scope",
    icon: CrosshairIcon,
    color: "text-accent-amber",
    borderColor: "border-accent-amber/30",
    bgColor: "bg-accent-amber/5",
    desc: "Map each advisory to affected endpoints using KB baseline and normalized software inventory. Know your exposure in seconds.",
  },
  {
    num: "03",
    name: "Decide",
    icon: ScaleIcon,
    color: "text-accent",
    borderColor: "border-accent/30",
    bgColor: "bg-accent/5",
    desc: "Transparent urgency scoring combines CVSS, EPSS, KEV status, and device criticality. Auto-deploy or route for approval.",
  },
  {
    num: "04",
    name: "Execute",
    icon: RocketIcon,
    color: "text-blue-400",
    borderColor: "border-blue-400/30",
    bgColor: "bg-blue-400/5",
    desc: "Ring rollout with canary, pilot, and broad stages. Automatic halt on anomaly detection. Three-path install fallback.",
  },
  {
    num: "05",
    name: "Verify",
    icon: ShieldCheckIcon,
    color: "text-accent-green",
    borderColor: "border-accent-green/30",
    bgColor: "bg-accent-green/5",
    desc: "Post-install KB check and app version confirmation. Before-and-after telemetry comparison. No silent failures.",
  },
  {
    num: "06",
    name: "Evidence",
    icon: DocumentIcon,
    color: "text-accent-violet",
    borderColor: "border-accent-violet/30",
    bgColor: "bg-accent-violet/5",
    desc: "Append-only audit log enforced at database level. MTTRem metrics, compliance exports, and NIS2 incident tracking.",
  },
];

export function SixStageLoop() {
  const sectionRef = useRef<HTMLElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.15 }
    );
    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <section id="loop" ref={sectionRef} className="py-24 lg:py-32 bg-bg-primary">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center max-w-3xl mx-auto mb-16">
          <p className="text-accent text-sm font-semibold tracking-widest uppercase mb-3">
            The Six-Stage Loop
          </p>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
            Signal to Evidence. Closed Loop.{" "}
            <span className="gradient-text">Every Time.</span>
          </h2>
          <p className="text-text-secondary text-lg">
            Most tools stop at &ldquo;patch deployed.&rdquo; PatchPilot doesn&rsquo;t close
            the loop until remediation is verified and the evidence is written.
          </p>
        </div>

        {/* Desktop: horizontal pipeline */}
        <div className="hidden lg:grid grid-cols-6 gap-4">
          {STAGES.map((stage, i) => {
            const Icon = stage.icon;
            return (
              <div
                key={stage.num}
                className={`relative rounded-xl border ${stage.borderColor} ${stage.bgColor} p-5 transition-all duration-500 ${
                  visible
                    ? "opacity-100 translate-y-0"
                    : "opacity-0 translate-y-6"
                }`}
                style={{ transitionDelay: `${i * 100}ms` }}
              >
                <span className={`text-xs font-mono ${stage.color} mb-2 block`}>
                  {stage.num}
                </span>
                <Icon className={`w-7 h-7 ${stage.color} mb-3`} />
                <h3 className="text-text-primary font-semibold mb-2">{stage.name}</h3>
                <p className="text-text-secondary text-sm leading-relaxed">{stage.desc}</p>

                {/* Connector arrow */}
                {i < STAGES.length - 1 && (
                  <div className="absolute -right-3 top-1/2 -translate-y-1/2 text-text-muted z-10">
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                      <path d="M2 6h8M7 3l3 3-3 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Mobile/Tablet: vertical timeline */}
        <div className="lg:hidden space-y-6">
          {STAGES.map((stage, i) => {
            const Icon = stage.icon;
            return (
              <div
                key={stage.num}
                className={`flex gap-4 transition-all duration-500 ${
                  visible
                    ? "opacity-100 translate-x-0"
                    : "opacity-0 -translate-x-4"
                }`}
                style={{ transitionDelay: `${i * 80}ms` }}
              >
                {/* Timeline connector */}
                <div className="flex flex-col items-center">
                  <div className={`w-10 h-10 rounded-full ${stage.bgColor} border ${stage.borderColor} flex items-center justify-center shrink-0`}>
                    <Icon className={`w-5 h-5 ${stage.color}`} />
                  </div>
                  {i < STAGES.length - 1 && (
                    <div className="w-px flex-1 bg-border mt-2" />
                  )}
                </div>
                <div className="pb-6">
                  <span className={`text-xs font-mono ${stage.color}`}>{stage.num}</span>
                  <h3 className="text-text-primary font-semibold">{stage.name}</h3>
                  <p className="text-text-secondary text-sm mt-1 leading-relaxed">{stage.desc}</p>
                </div>
              </div>
            );
          })}
        </div>

        {/* Zero-day callout */}
        <div
          className={`mt-12 glow-card p-6 lg:p-8 transition-all duration-700 ${
            visible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-6"
          }`}
          style={{ transitionDelay: "600ms" }}
        >
          <div className="flex items-start gap-4">
            <div className="w-10 h-10 rounded-lg bg-accent-amber/10 border border-accent-amber/30 flex items-center justify-center shrink-0">
              <span className="text-accent-amber text-lg font-bold">!</span>
            </div>
            <div>
              <h4 className="text-text-primary font-semibold mb-1">Zero-Day Off-Ramp</h4>
              <p className="text-text-secondary text-sm leading-relaxed">
                When no patch exists, PatchPilot creates an UnpatchedExposure &mdash; a first-class
                entity with its own state machine, recheck loop, and mitigation evidence trail.
                The loop never exits just because there is nothing to install.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
