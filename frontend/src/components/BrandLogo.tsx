
type BrandLogoProps = {
  compact?: boolean
}

export default function BrandLogo({ compact = false }: BrandLogoProps) {
  return (
    <div className="flex items-center gap-3">
      <svg
        viewBox="0 0 120 140"
      width={compact ? 72 : 96}
      height={compact ? 84 : 112}
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-label="AI Shield emblem"
        role="img"
      >
        <path
          d="M60 7 L105 25 V67 C105 96 86 118 60 132 C34 118 15 96 15 67 V25 Z"
          fill="#111214"
          stroke="#E52B35"
          strokeWidth="5"
        />
        <path
          d="M60 17 L94 31 V66 C94 88 80 106 60 118"
          stroke="#777777"
          strokeWidth="3"
        />
        <g stroke="#FF303B" strokeWidth="3.5" strokeLinecap="round">
          <path d="M60 38 L37 53 L60 69 L83 53 Z" />
          <path d="M37 53 V78 M83 53 V78 M60 69 V96" />
          <path d="M37 78 L60 96 L83 78" />
        </g>
        <g fill="#FF303B">
          <circle cx="60" cy="38" r="6" />
          <circle cx="37" cy="53" r="6" />
          <circle cx="83" cy="53" r="6" />
          <circle cx="60" cy="69" r="7" />
          <circle cx="37" cy="78" r="6" />
          <circle cx="83" cy="78" r="6" />
          <circle cx="60" cy="96" r="6" />
        </g>
        <path
          d="M9 77 C30 103 88 101 111 68"
          stroke="#FF303B"
          strokeWidth="8"
          strokeLinecap="round"
        />
        <path
          d="M9 77 C30 103 88 101 111 68"
          stroke="#FF9298"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
      </svg>

      {!compact && (
        <div className="flex flex-col gap-1">
          <div className="text-2xl font-bold tracking-wider text-white">
            <span className="text-red-500">AI</span> SHIELD
          </div>
          <div className="text-[10px] font-semibold tracking-[2px] text-gray-400">
            YOUR SECURITY. OUR PRIORITY.
          </div>
        </div>
      )}
    </div>
  )
}
