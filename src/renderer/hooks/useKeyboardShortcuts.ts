import { useCallback, useEffect } from 'react';

export interface ShortcutBinding {
  key: string;
  ctrl?: boolean;
  meta?: boolean;
  shift?: boolean;
  alt?: boolean;
  /** If true, shortcut runs even when focus is in input/textarea (e.g. Ctrl+F to focus search). */
  allowInInput?: boolean;
  handler: () => void;
}

const isMac = typeof navigator !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.platform);

function matches(b: ShortcutBinding, e: KeyboardEvent): boolean {
  const keyOk =
    b.key.toLowerCase() === e.key.toLowerCase() ||
    (b.key === 'Esc' && (e.key === 'Esc' || e.key === 'Escape'));
  if (!keyOk) return false;
  const mod = isMac ? e.metaKey : e.ctrlKey;
  if (b.ctrl && !mod) return false;
  if (b.shift && !e.shiftKey) return false;
  if (b.alt && !e.altKey) return false;
  return true;
}

export function useKeyboardShortcuts(bindings: ShortcutBinding[], enabled = true) {
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (!enabled) return;
      const target = e.target as HTMLElement;
      const inInput = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable;
      for (const b of bindings) {
        if (!matches(b, e)) continue;
        if (inInput && !b.allowInInput && b.key !== 'Esc' && b.key !== 'Escape') continue;
        e.preventDefault();
        b.handler();
        return;
      }
    },
    [enabled, bindings]
  );

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);
}
