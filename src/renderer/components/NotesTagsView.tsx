import React, { useState, useEffect, memo } from 'react';
import { HttpRequest } from '../../main/proxy-server';
import { requestDetailEqual } from '../utils/requestEqual';
import NotesTags from './NotesTags';
import { EmptyState } from './EmptyState';
import { useToast } from '../context/ToastContext';
import './NotesTagsView.css';

interface NotesTagsViewProps {
  request: HttpRequest | null;
}

const NotesTagsView: React.FC<NotesTagsViewProps> = ({ request }) => {
  const [requestDetails, setRequestDetails] = useState<HttpRequest | null>(request);
  const toast = useToast();

  useEffect(() => {
    setRequestDetails(request);
  }, [request]);

  if (!requestDetails) {
    return (
      <div className="notes-tags-view">
        <div className="empty-state">
          <EmptyState icon="notes" title="Select a request to add notes and tags" brandName="CleanTraffic" />
        </div>
      </div>
    );
  }

  const getHost = (url: string): string => {
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  };

  const getPath = (url: string): string => {
    try {
      const urlObj = new URL(url);
      return urlObj.pathname + urlObj.search;
    } catch {
      return url;
    }
  };

  const getMethodColor = (method: string): string => {
    const colors: Record<string, string> = {
      GET: 'hsl(210, 12%, 45%)',
      POST: '#ff4444',
      PUT: '#cc7722',
      DELETE: '#cc2244',
      PATCH: '#884499',
      HEAD: 'hsl(210, 10%, 55%)',
      OPTIONS: 'hsl(210, 10%, 55%)',
    };
    return colors[method.toUpperCase()] || 'hsl(210, 10%, 55%)';
  };

  const getStatusColor = (status?: number): string => {
    if (!status) return '#999999';
    if (status >= 200 && status < 300) return '#2ecc71';
    if (status >= 300 && status < 400) return '#3498db';
    if (status >= 400 && status < 500) return '#f39c12';
    if (status >= 500) return '#e74c3c';
    return '#999999';
  };

  return (
    <div className="notes-tags-view">
      <div className="notes-tags-header">
        <div className="header-left">
          <h2>Notes & Tags</h2>
          <p className="notes-header-hint">Add notes and tags here. Use &quot;Send to Notes&quot; in Scanner to append findings.</p>
          <div className="request-info-bar">
            <span className="method-badge" style={{ backgroundColor: getMethodColor(requestDetails.method) }}>
              {requestDetails.method}
            </span>
            <span className="host-name">{getHost(requestDetails.url)}</span>
            <span className="path-name">{getPath(requestDetails.url)}</span>
            {requestDetails.status && (
              <span className="status-badge" style={{ color: getStatusColor(requestDetails.status) }}>
                {requestDetails.status}
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="notes-tags-content">
        <NotesTags request={requestDetails} onUpdate={async (requestId, notes, tags) => {
          try {
            const res = await (window as any).electronAPI.updateRequestNotesTags?.(requestId, notes, tags);
            if (res?.success) {
              setRequestDetails((prev) => (prev ? { ...prev, notes, tags } : null));
            } else if (res?.error) {
              toast.error(res.error);
            }
          } catch (e) {
            toast.error(e instanceof Error ? e.message : 'Failed to update notes/tags');
          }
        }} />
      </div>
    </div>
  );
};

export default memo(NotesTagsView, (prev, next) => requestDetailEqual(prev.request, next.request));

