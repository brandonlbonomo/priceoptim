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
    "bg-hunter text-ivory hover:bg-hunter-light active:scale-[0.98]",
  secondary:
    "bg-ivory text-hunter hover:bg-white active:scale-[0.98]",
  outline:
    "border border-hunter/25 text-hunter bg-transparent hover:border-hunter/50 hover:bg-hunter/[0.03] active:scale-[0.98]",
  ghost: "text-hunter hover:bg-hunter/[0.04] active:scale-[0.98]",
};

const sizeStyles: Record<ButtonSize, string> = {
  sm: "px-5 py-2.5 text-[11px]",
  md: "px-7 py-3 text-[12px]",
  lg: "px-9 py-3.5 text-[12px]",
};

export function Button({
  variant = "primary",
  size = "md",
  className,
  children,
  ...props
}: ButtonProps) {
  const classes = cn(
    "inline-flex items-center justify-center font-semibold uppercase tracking-[0.16em] rounded-[2px] transition-[color,background-color,border-color,box-shadow,transform,opacity] duration-500 ease-[cubic-bezier(0.23,1,0.32,1)] focus:outline-none focus-visible:ring-2 focus-visible:ring-gold/40 focus-visible:ring-offset-2",
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
