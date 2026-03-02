import { Hero } from "@/components/landing/Hero";
import { SixStageLoop } from "@/components/landing/SixStageLoop";
import {
  TrustBar,
  ProblemSolution,
  MetricsStats,
  FeaturesGrid,
  RingRolloutVisual,
  ComplianceSection,
  ComparisonTable,
  TestimonialSection,
  FinalCTA,
  Footer,
} from "@/components/landing/sections";

export default function Home() {
  return (
    <main>
      <Hero />
      <TrustBar />
      <ProblemSolution />
      <SixStageLoop />
      <MetricsStats />
      <FeaturesGrid />
      <RingRolloutVisual />
      <ComplianceSection />
      <ComparisonTable />
      <TestimonialSection />
      <FinalCTA />
      <Footer />
    </main>
  );
}
