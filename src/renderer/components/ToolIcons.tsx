import React from 'react';
import './ToolIcons.css';

const stroke = { stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const, fill: 'none' };

/** Tool-specific empty-state glyphs: unique, coherent, security/tool themed */
export const EmptyGlyph: React.FC<{ kind: string }> = ({ kind }) => {
  const props = { ...stroke, stroke: '#0b1220' };
  const white = { fill: 'white', opacity: 0.94 };
  switch (kind) {
    case 'intruder':
      return (
        <g>
          <circle cx="12" cy="12" r="6" {...props} />
          <path d="M12 6v12M6 12h12" {...props} />
          <path d="M12 8.5v7M8.5 12h7" {...{ ...props, strokeWidth: 1.2 }} />
          <circle cx="12" cy="12" r="1.5" fill="#0b1220" />
        </g>
      );
    case 'sequencer':
      return (
        <g stroke="#0b1220" strokeWidth="2" strokeLinecap="round" fill="none">
          <path d="M6 8v8M12 6v12M18 10v4" />
        </g>
      );
    case 'scanner':
      return (
        <g>
          <path d="M12 3L4 6v6c0 4 4 7.5 8 9 4-1.5 8-5 8-9V6l-8-3z" fill="white" opacity="0.94" stroke="#0b1220" strokeWidth="1.2" fillRule="evenodd" />
          <path d="M8 10h8M9 13h6" {...props} stroke="#0b1220" />
          <circle cx="12" cy="9" r="1.2" fill="#0b1220" />
        </g>
      );
    case 'extractor':
      return (
        <g>
          <path d="M7 4h10l4 6v8H3v-8l4-6z" {...props} stroke="#0b1220" />
          <path d="M7 4l4 6h6l4-6" stroke="#0b1220" strokeWidth="1.4" />
          <circle cx="9" cy="14" r="1.2" fill="#0b1220" />
          <circle cx="12" cy="14" r="1.2" fill="#0b1220" />
          <circle cx="15" cy="14" r="1.2" fill="#0b1220" />
        </g>
      );
    case 'analyzer':
      return (
        <g>
          <path d="M12 2L4 5v6c0 4 4 7.5 8 9 4-1.5 8-5 8-9V5l-8-3z" fill="white" opacity="0.94" stroke="#0b1220" strokeWidth="1.2" fillRule="evenodd" />
          <path d="M10 11l2 2 4-4" {...props} stroke="#0b1220" strokeWidth="2" />
        </g>
      );
    case 'notes':
      return (
        <g>
          <path d="M8 2h8l4 4v12H4V2h4z" fill="white" opacity="0.94" stroke="#0b1220" strokeWidth="1.2" fillRule="evenodd" />
          <path d="M8 2v4h8" stroke="#0b1220" strokeWidth="1.2" />
          <path d="M8 10h8M8 13h5" {...props} stroke="#0b1220" />
        </g>
      );
    case 'inbox':
      return (
        <g>
          <path d="M4 6h16l2 4v8H2v-8l2-4z" fill="white" opacity="0.94" stroke="#0b1220" strokeWidth="1.2" fillRule="evenodd" />
          <path d="M4 10h16M8 14h8" stroke="#0b1220" strokeWidth="1.4" strokeLinecap="round" fill="none" />
        </g>
      );
    case 'spark':
      return (
        <g>
          <path d="M12 3l9 4.5v9c0 6.2-4 11.7-9 14-5-2.3-9-7.8-9-14v-9L12 3z" fill="white" opacity="0.94" />
          <path d="M12 10l1 2.2 2.4.2-1.8 1.5.6 2.3L12 15l-2.2 1.2.6-2.3-1.8-1.5 2.4-.2L12 10z" fill="#0b1220" />
        </g>
      );
    default:
      return (
        <g>
          <path d="M12 3l9 4.5v9c0 6.2-4 11.7-9 14-5-2.3-9-7.8-9-14v-9L12 3z" {...white} />
          <path d="M12 10l1 2.2 2.4.2-1.8 1.5.6 2.3L12 15l-2.2 1.2.6-2.3-1.8-1.5 2.4-.2L12 10z" fill="#0b1220" />
        </g>
      );
  }
};

/** Badge + glyph for empty states */
export const EmptyBadge: React.FC<{ kind: string }> = ({ kind }) => (
  <svg className="tool-empty-badge" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <defs>
      <linearGradient id="toolBadgeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stopColor="#ff5555" />
        <stop offset="100%" stopColor="#cc2222" />
      </linearGradient>
    </defs>
    <rect x="1.2" y="1.2" width="21.6" height="21.6" rx="6" fill="url(#toolBadgeGrad)" />
    <EmptyGlyph kind={kind} />
  </svg>
);

/** Scanner loading: shield + rotating beam (unique, not generic spinner) */
export const ScanLoader: React.FC<{ label?: string; badge?: string }> = ({ label = 'Starting scan…', badge }) => (
  <div className="tool-scan-loader">
    <div className="tool-scan-loader-icon" aria-hidden="true">
      <svg viewBox="0 0 48 48" fill="none">
        <defs>
          <linearGradient id="scanShieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#ff5555" />
            <stop offset="100%" stopColor="#cc2222" />
          </linearGradient>
        </defs>
        <path d="M24 4L8 10v12c0 10 8 18 16 20 8-2 16-10 16-20V10L24 4z" fill="url(#scanShieldGrad)" fillOpacity="0.2" stroke="#ff4444" strokeWidth="2" strokeLinejoin="round" />
        <g transform="translate(24, 20)" className="tool-scan-beam">
          <circle r="12" fill="none" stroke="#ff4444" strokeWidth="2" strokeDasharray="4 6" />
        </g>
      </svg>
    </div>
    {label && <span className="tool-scan-label">{label}</span>}
    {badge && <span className="tool-scan-badge">{badge}</span>}
  </div>
);

/** Filtered-empty: funnel icon */
export const FilterEmptyIcon: React.FC = () => (
  <svg className="tool-filter-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M4 4h16l-4 8v6l-4 2v-8L4 4z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" fill="none" />
  </svg>
);

/** Repeater "Sending..." mini loader */
export const SendLoader: React.FC = () => (
  <span className="tool-send-loader" aria-hidden="true">
    <svg viewBox="0 0 20 20" fill="none">
      <circle cx="10" cy="10" r="7" stroke="currentColor" strokeWidth="2" fill="none" strokeDasharray="3 5" className="tool-send-spin" />
    </svg>
  </span>
);

const headerStroke = { stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const, fill: 'none' };

/** Unique header icons per tool */
export const IntruderHeaderIcon: React.FC = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="tool-header-icon intruder-header-icon" aria-hidden="true">
    <circle cx="12" cy="12" r="7" {...headerStroke} />
    <path d="M12 5v14M5 12h14" {...headerStroke} />
    <path d="M12 8.5v7M8.5 12h7" {...{ ...headerStroke, strokeWidth: 1.2 }} />
    <circle cx="12" cy="12" r="2" fill="currentColor" />
  </svg>
);

export const SequencerHeaderIcon: React.FC = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="tool-header-icon sequencer-header-icon" aria-hidden="true">
    <path d="M6 8v8M12 6v12M18 10v4" {...headerStroke} />
  </svg>
);

export const ExtractorHeaderIcon: React.FC = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="tool-header-icon extractor-header-icon" aria-hidden="true">
    <path d="M7 4h10l4 6v8H3v-8l4-6z" {...headerStroke} />
    <path d="M7 4l4 6h6l4-6" {...{ ...headerStroke, strokeWidth: 1.4 }} />
    <circle cx="9" cy="14" r="1.2" fill="currentColor" />
    <circle cx="12" cy="14" r="1.2" fill="currentColor" />
    <circle cx="15" cy="14" r="1.2" fill="currentColor" />
  </svg>
);

export const AnalyzerHeaderIcon: React.FC = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="tool-header-icon analyzer-header-icon" aria-hidden="true">
    <path d="M12 2L4 5v6c0 4 4 7.5 8 9 4-1.5 8-5 8-9V5l-8-3z" fill="currentColor" fillOpacity="0.2" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
    <path d="M10 11l2 2 4-4" {...{ ...headerStroke, strokeWidth: 2 }} />
  </svg>
);
