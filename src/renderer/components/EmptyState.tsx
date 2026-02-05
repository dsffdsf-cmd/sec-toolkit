import React from 'react';
import { EmptyBadge } from './ToolIcons';
import './EmptyState.css';

export type EmptyStateIcon =
  | 'inbox'
  | 'spark'
  | 'hash'
  | 'intruder'
  | 'sequencer'
  | 'scanner'
  | 'extractor'
  | 'analyzer'
  | 'notes';

const iconToKind: Record<EmptyStateIcon, string> = {
  inbox: 'inbox',
  spark: 'spark',
  hash: 'sequencer',
  intruder: 'intruder',
  sequencer: 'sequencer',
  scanner: 'scanner',
  extractor: 'extractor',
  analyzer: 'analyzer',
  notes: 'notes',
};

export const EmptyState: React.FC<{
  icon: EmptyStateIcon;
  title: string;
  subtitle?: string;
  brandName?: string;
}> = ({ icon, title, subtitle, brandName = 'CleanTraffic' }) => {
  const kind = iconToKind[icon];
  return (
    <div className="empty-state-v2">
      <EmptyBadge kind={kind} />
      <div className="empty-title">{title}</div>
      {subtitle && <div className="empty-subtitle">{subtitle}</div>}
      <div className="empty-brand">{brandName}</div>
    </div>
  );
};
