import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { SettingsProvider } from './context/SettingsContext';
import { ToastProvider } from './context/ToastContext';

const root = ReactDOM.createRoot(document.getElementById('root')!);
root.render(
  <React.StrictMode>
    <SettingsProvider>
      <ToastProvider>
        <App />
      </ToastProvider>
    </SettingsProvider>
  </React.StrictMode>
);

