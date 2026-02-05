import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { ToastContainer } from '../components/Toast';

export type ToastType = 'success' | 'error' | 'info';

export interface ToastItem {
  id: string;
  type: ToastType;
  message: string;
  duration?: number;
  action?: { label: string; onClick: () => void };
}

interface ToastContextValue {
  toast: (msg: string, type?: ToastType, opts?: { duration?: number; action?: { label: string; onClick: () => void } }) => void;
  success: (msg: string, opts?: { duration?: number }) => void;
  error: (msg: string, opts?: { duration?: number }) => void;
  info: (msg: string, opts?: { duration?: number }) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const DEFAULT_DURATION = 4000;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);

  const remove = useCallback((id: string) => {
    setItems((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const add = useCallback(
    (
      message: string,
      type: ToastType = 'info',
      opts?: { duration?: number; action?: { label: string; onClick: () => void } }
    ) => {
      const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
      const duration = opts?.duration ?? DEFAULT_DURATION;
      setItems((prev) => [...prev, { id, type, message, duration, action: opts?.action }]);
      if (duration > 0) {
        setTimeout(() => remove(id), duration);
      }
    },
    [remove]
  );

  const success = useCallback((msg: string, opts?: { duration?: number }) => add(msg, 'success', opts), [add]);
  const error = useCallback((msg: string, opts?: { duration?: number }) => add(msg, 'error', { ...opts, duration: opts?.duration ?? 6000 }), [add]);
  const info = useCallback((msg: string, opts?: { duration?: number }) => add(msg, 'info', opts), [add]);

  const value = useMemo(
    () => ({ toast: add, success, error, info }),
    [add, success, error, info]
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastContainer items={items} onDismiss={remove} />
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}
