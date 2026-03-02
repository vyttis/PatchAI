import { ArrowRightIcon } from "@/components/landing/icons";

interface ButtonProps {
  variant?: "primary" | "secondary" | "ghost";
  size?: "sm" | "md" | "lg";
  href?: string;
  children: React.ReactNode;
  className?: string;
  showArrow?: boolean;
}

const base =
  "inline-flex items-center justify-center font-semibold rounded-lg transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-accent/50 focus:ring-offset-2 focus:ring-offset-bg-primary";

const variants = {
  primary:
    "bg-accent text-bg-primary hover:bg-accent-bright shadow-lg shadow-accent/20 hover:shadow-accent/30",
  secondary:
    "border border-accent/40 text-accent hover:bg-accent/10 hover:border-accent",
  ghost:
    "text-text-secondary hover:text-text-primary",
};

const sizes = {
  sm: "px-4 py-2 text-sm gap-1.5",
  md: "px-6 py-3 text-sm gap-2",
  lg: "px-8 py-4 text-base gap-2",
};

export function Button({
  variant = "primary",
  size = "md",
  href,
  children,
  className = "",
  showArrow = false,
}: ButtonProps) {
  const classes = `${base} ${variants[variant]} ${sizes[size]} ${className}`;

  const content = (
    <>
      {children}
      {showArrow && <ArrowRightIcon className="w-4 h-4" />}
    </>
  );

  if (href) {
    return (
      <a href={href} className={classes}>
        {content}
      </a>
    );
  }
  return (
    <button className={classes}>
      {content}
    </button>
  );
}
