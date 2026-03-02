import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://app.patchpilot.com"),
  title: "PatchPilot | Exploit-to-Remediation Automation for EU Windows Fleets",
  description:
    "Fastest path from CISA KEV alert to verified patch. Ring rollout, append-only audit, GDPR + NIS2 compliance. Built for 500-5,000 endpoint fleets. EU-hosted in Frankfurt.",
  keywords: [
    "patch management",
    "exploit remediation",
    "CISA KEV",
    "Windows patch automation",
    "NIS2 compliance",
    "GDPR patch management",
    "MTTRem",
    "ring rollout",
    "vulnerability remediation",
    "EU SaaS security",
  ],
  openGraph: {
    title: "PatchPilot | From KEV Alert to Verified Patch in Under 2 Hours",
    description:
      "Exploit-to-Remediation Automation Platform for EU Windows fleets. GDPR + NIS2 ready.",
    url: "https://app.patchpilot.com",
    siteName: "PatchPilot",
    type: "website",
    locale: "en_US",
  },
  twitter: {
    card: "summary_large_image",
    title: "PatchPilot | Exploit-to-Remediation Automation",
    description:
      "From CISA KEV alert to verified patch in under 2 hours.",
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="font-sans antialiased">{children}</body>
    </html>
  );
}
