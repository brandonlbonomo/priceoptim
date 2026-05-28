import { cn } from "@/lib/utils";
import Link from "next/link";

type ButtonVariant = "primary" | "secondary" | "outline" | "ghost";
type ButtonSize = "sm" | "md" | "lg";

type ButtonProps = {
  variant?: ButtonVariant;
  size?: ButtonSize;
  className?: string;
  children: React.ReactNode;
} & (
  | { href: string; disabled?: never; type?: never; onClick?: never }
  | {
      href?: never;
      disabled?: boolean;
      type?: "button" | "submit" | "reset";
      onClick?: React.MouseEventHandler<HTMLButtonElement>;
    }
);

const variantStyles: Record<ButtonVariant, string> = {
  primary:
    "bg-primary text-white shadow-lg shadow-primary/20 hover:bg-primary-light hover:shadow-xl hover:shadow-primary/25 hover:-translate-y-0.5 active:translate-y-0",
  secondary:
    "bg-accent text-primary-dark shadow-lg shadow-accent/20 hover:bg-accent-light hover:shadow-xl hover:shadow-accent/25 hover:-translate-y-0.5 active:translate-y-0",
  outline:
    "border border-primary/20 text-primary bg-white/50 backdrop-blur-sm hover:bg-primary hover:text-white hover:border-primary hover:-translate-y-0.5 active:translate-y-0",
  ghost: "text-primary hover:bg-primary/5",
};

const sizeStyles: Record<ButtonSize, string> = {
  sm: "px-5 py-2.5 text-sm",
  md: "px-7 py-3 text-base",
  lg: "px-9 py-4 text-lg",
};

export function Button({
  variant = "primary",
  size = "md",
  className,
  children,
  ...props
}: ButtonProps) {
  const classes = cn(
    "inline-flex items-center justify-center font-semibold rounded-2xl transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-primary/30 focus:ring-offset-2",
    variantStyles[variant],
    sizeStyles[size],
    className,
  );

  if ("href" in props && props.href) {
    return (
      <Link href={props.href} className={classes}>
        {children}
      </Link>
    );
  }

  return (
    <button className={classes} disabled={props.disabled} type={props.type} onClick={props.onClick}>
      {children}
    </button>
  );
}
