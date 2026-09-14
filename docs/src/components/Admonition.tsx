import { type ReactNode } from "react";
import { InfoIcon, CheckIcon, AlertTriangleIcon, DangerIcon } from "./icons";

const ADM_CONFIG: Record<
  string,
  { bg: string; border: string; icon: ReactNode; label: string }
> = {
  note: {
    bg: "var(--info-bg)",
    border: "var(--info-border)",
    icon: <InfoIcon />,
    label: "Note",
  },
  info: {
    bg: "var(--info-bg)",
    border: "var(--info-border)",
    icon: <InfoIcon />,
    label: "Info",
  },
  tip: {
    bg: "var(--tip-bg)",
    border: "var(--tip-border)",
    icon: <CheckIcon />,
    label: "Tip",
  },
  warning: {
    bg: "var(--warn-bg)",
    border: "var(--warn-border)",
    icon: <AlertTriangleIcon />,
    label: "Warning",
  },
  danger: {
    bg: "var(--danger-bg)",
    border: "var(--danger-border)",
    icon: <DangerIcon />,
    label: "Danger",
  },
  deprecated: {
    bg: "var(--danger-bg)",
    border: "var(--danger-border)",
    icon: <AlertTriangleIcon />,
    label: "Deprecated",
  },
};

export function Admonition({
  type = "note",
  label,
  children,
}: {
  type?: string;
  label?: string;
  children: ReactNode;
}) {
  const config = ADM_CONFIG[type] || ADM_CONFIG.note;
  const title = label ?? config.label;

  return (
    <div
      style={{
        background: config.bg,
        borderLeft: `3px solid ${config.border}`,
        borderRadius: "0 6px 6px 0",
        padding: "12px 16px",
        margin: "16px 0",
        fontSize: "0.875rem",
        lineHeight: 1.6,
        color: "var(--text-2)",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          marginBottom: 6,
          fontWeight: 600,
          color: "var(--text)",
          fontSize: "0.8125rem",
        }}
      >
        {config.icon}
        {title}
      </div>
      {children}
    </div>
  );
}