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
    "bg-foreground text-white hover:bg-primary-light active:scale-[0.97]",
  secondary:
    "bg-accent text-white hover:bg-accent-light active:scale-[0.97]",
  outline:
    "border border-black/10 text-foreground bg-white/60 backdrop-blur-sm hover:bg-white active:scale-[0.97]",
  ghost: "text-foreground hover:bg-black/[0.03] active:scale-[0.97]",
};

const sizeStyles: Record<ButtonSize, string> = {
  sm: "px-5 py-2 text-[13px]",
  md: "px-7 py-2.5 text-[14px]",
  lg: "px-8 py-3 text-[15px]",
};

export function Button({
  variant = "primary",
  size = "md",
  className,
  children,
  ...props
}: ButtonProps) {
  const classes = cn(
    "inline-flex items-center justify-center font-medium tracking-wide rounded-full transition-[color,background-color,border-color,box-shadow,transform,opacity] duration-500 ease-[cubic-bezier(0.23,1,0.32,1)] focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 focus-visible:ring-offset-2",
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
