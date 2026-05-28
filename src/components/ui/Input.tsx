import { cn } from "@/lib/utils";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

export function Input({ label, error, className, id, ...props }: InputProps) {
  return (
    <div className="w-full">
      {label && (
        <label htmlFor={id} className="mb-1.5 block text-sm font-medium text-foreground">
          {label}
        </label>
      )}
      <input
        id={id}
        className={cn(
          "w-full rounded-2xl border border-gray-200 bg-white px-5 py-3 text-foreground placeholder-muted transition-all duration-200 focus:border-primary/40 focus:outline-none focus:ring-2 focus:ring-primary/15",
          error && "border-red-400 focus:border-red-400 focus:ring-red-400/15",
          className,
        )}
        {...props}
      />
      {error && <p className="mt-1.5 text-sm text-red-500">{error}</p>}
    </div>
  );
}
