import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "PatchPilot",
  description: "Exploit-to-Remediation Automation Platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
