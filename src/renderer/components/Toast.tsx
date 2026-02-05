import React from 'react';
import type { ToastItem } from '../context/ToastContext';
import './Toast.css';

export function ToastContainer({
  items,
  onDismiss,
}: {
  items: ToastItem[];
  onDismiss: (id: string) => void;
}) {
  return (
    <div className="toast-container" role="region" aria-label="Notifications">
      {items.map((t) => (
        <Toast key={t.id} item={t} onDismiss={() => onDismiss(t.id)} />
      ))}
    </div>
  );
}

export function Toast({
  item,
  onDismiss,
}: {
  item: ToastItem;
  onDismiss: () => void;
}) {
  const { type, message, action } = item;

  return (
    <div
      className={`toast toast-${type}`}
      role="alert"
      data-type={type}
    >
      <span className="toast-message">{message}</span>
      {action && (
        <button
          type="button"
          className="toast-action"
          onClick={() => {
            action.onClick();
            onDismiss();
          }}
        >
          {action.label}
        </button>
      )}
      <button
        type="button"
        className="toast-dismiss"
        onClick={onDismiss}
        aria-label="Dismiss"
      >
        ×
      </button>
    </div>
  );
}
