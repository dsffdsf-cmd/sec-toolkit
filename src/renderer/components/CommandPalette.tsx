import React, { useState, useEffect, useRef, useCallback } from 'react';
import './CommandPalette.css';

export type CommandPaletteAction =
  | { type: 'view'; id: string; label: string }
  | { type: 'save-session'; id: string; label: string }
  | { type: 'export-har'; id: string; label: string }
  | { type: 'export-postman'; id: string; label: string }
  | { type: 'settings'; id: string; label: string };

export interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  onAction: (action: CommandPaletteAction) => void;
  viewLabels: { id: string; label: string }[];
  canSaveSession?: boolean;
  canExportHar?: boolean;
  canExportPostman?: boolean;
}

export function CommandPalette({
  open,
  onClose,
  onAction,
  viewLabels,
  canSaveSession = true,
  canExportHar = true,
  canExportPostman = true,
}: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // One entry per command: views first, then session/export/settings (no duplicates by type+id)
  const viewActions: CommandPaletteAction[] = viewLabels.map((v) => ({ type: 'view', id: v.id, label: v.label }));
  const sessionExportActions: CommandPaletteAction[] = [
    ...(canSaveSession ? [{ type: 'save-session' as const, id: 'save-session', label: 'Save session' }] : []),
    ...(canExportHar ? [{ type: 'export-har' as const, id: 'export-har', label: 'Export to HAR' }] : []),
    ...(canExportPostman ? [{ type: 'export-postman' as const, id: 'export-postman', label: 'Export to Postman' }] : []),
    { type: 'settings', id: 'settings', label: 'Open Settings' },
  ];
  const allActions = [...viewActions, ...sessionExportActions];

  const filtered = query.trim()
    ? allActions.filter(
        (a) => a.label.toLowerCase().includes(query.toLowerCase().trim())
      )
    : allActions;

  const runAction = useCallback(
    (action: CommandPaletteAction) => {
      onAction(action);
      onClose();
      setQuery('');
      setSelectedIndex(0);
    },
    [onAction, onClose]
  );

  useEffect(() => {
    if (!open) return;
    setQuery('');
    setSelectedIndex(0);
    setTimeout(() => inputRef.current?.focus(), 50);
  }, [open]);

  useEffect(() => {
    setSelectedIndex((i) => (filtered.length ? Math.min(i, filtered.length - 1) : 0));
  }, [filtered.length, query]);

  useEffect(() => {
    if (!open) return;
    const el = listRef.current;
    if (!el) return;
    const child = el.children[selectedIndex] as HTMLElement | undefined;
    child?.scrollIntoView({ block: 'nearest' });
  }, [open, selectedIndex, filtered]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
      return;
    }
    const len = filtered.length;
    if (len === 0) return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((i) => (i + 1) % len);
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((i) => (i - 1 + len) % len);
      return;
    }
    if (e.key === 'Enter') {
      const action = filtered[selectedIndex];
      if (action) {
        e.preventDefault();
        runAction(action);
      }
    }
  };

  if (!open) return null;

  return (
    <div className="command-palette-overlay" onClick={onClose} role="presentation">
      <div
        className="command-palette"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label="Command palette"
      >
        <input
          ref={inputRef}
          type="text"
          className="command-palette-input"
          placeholder="Search commands…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          aria-autocomplete="list"
          aria-controls="command-palette-list"
          aria-activedescendant={filtered[selectedIndex] ? `cmd-${selectedIndex}` : undefined}
        />
        <div id="command-palette-list" ref={listRef} className="command-palette-list" role="listbox">
          {filtered.length === 0 ? (
            <div className="command-palette-item empty">No matches</div>
          ) : (
            filtered.map((action, i) => (
              <button
                key={`${action.type}-${action.id}`}
                type="button"
                id={`cmd-${i}`}
                className={`command-palette-item ${i === selectedIndex ? 'selected' : ''}`}
                role="option"
                aria-selected={i === selectedIndex}
                onClick={() => runAction(action)}
                onMouseEnter={() => setSelectedIndex(i)}
              >
                <span className="command-palette-item-label">{action.label}</span>
                <span className="command-palette-item-hint">
                  {action.type === 'view'
                    ? 'View'
                    : action.type === 'save-session'
                      ? 'Session'
                      : action.type === 'export-har'
                        ? 'HAR file'
                        : action.type === 'export-postman'
                          ? 'Postman'
                          : action.type === 'settings'
                            ? 'Settings'
                            : ''}
                </span>
              </button>
            ))
          )}
        </div>
        <div className="command-palette-footer">
          <kbd>↑↓</kbd> Navigate <kbd>Enter</kbd> Run <kbd>Esc</kbd> Close
        </div>
      </div>
    </div>
  );
}
