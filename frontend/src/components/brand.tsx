import { cn } from "@/lib/utils"

export function Brand({ collapsed = false, className }: { collapsed?: boolean; className?: string }) {
  return (
    <div className={cn("flex items-center gap-2.5", className)} aria-label="AppGuard by Servasec">
      <img src="/assets/appguard-mark.svg" alt="" className="h-7 w-7 shrink-0" />
      {!collapsed && (
        <span className="flex flex-col leading-tight">
          <span className="text-sm font-semibold tracking-tight text-foreground">AppGuard</span>
          <span className="text-[10px] text-muted-foreground">by Servasec</span>
        </span>
      )}
    </div>
  )
}
