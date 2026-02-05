import React, { Component, ErrorInfo, ReactNode } from 'react';
import './ErrorBoundary.css';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
  /** Optional label for this boundary (e.g. "Scanner", "Repeater") */
  label?: string;
}

interface State {
  error: Error | null;
  errorInfo: ErrorInfo | null;
  expanded: boolean;
  copied: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = {
    error: null,
    errorInfo: null,
    expanded: false,
    copied: false,
  };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    this.setState({ errorInfo });
    this.props.onError?.(error, errorInfo);
  }

  handleRetry = (): void => {
    this.setState({ error: null, errorInfo: null, expanded: false, copied: false });
  };

  handleCopy = async (): Promise<void> => {
    const { error, errorInfo } = this.state;
    if (!error) return;
    const text = [
      error.toString(),
      error.stack || '',
      errorInfo?.componentStack ? `\nComponent stack:\n${errorInfo.componentStack}` : '',
    ].join('\n');
    try {
      await navigator.clipboard.writeText(text);
      this.setState({ copied: true });
      setTimeout(() => this.setState({ copied: false }), 2000);
    } catch {
      /* ignore */
    }
  };

  render(): ReactNode {
    const { error, errorInfo, expanded, copied } = this.state;
    const { children, fallback, label } = this.props;

    if (!error) return children;

    if (fallback) return fallback;

    const stack = error.stack || '';
    const componentStack = errorInfo?.componentStack || '';

    return (
      <div className="error-boundary" role="alert">
        <div className="error-boundary-header">
          <span className="error-boundary-icon" aria-hidden>⚠</span>
          <div className="error-boundary-title-row">
            <h3 className="error-boundary-title">
              {label ? `${label} failed` : 'Something went wrong'}
            </h3>
            <button
              type="button"
              className="error-boundary-btn primary"
              onClick={this.handleRetry}
            >
              Try again
            </button>
          </div>
        </div>
        <p className="error-boundary-message">{error.message}</p>
        <div className="error-boundary-actions">
          <button
            type="button"
            className="error-boundary-btn secondary"
            onClick={() => this.setState({ expanded: !expanded })}
          >
            {expanded ? 'Hide details' : 'Show details'}
          </button>
          <button
            type="button"
            className="error-boundary-btn secondary"
            onClick={this.handleCopy}
          >
            {copied ? 'Copied' : 'Copy error'}
          </button>
        </div>
        {expanded && (
          <div className="error-boundary-details">
            {stack && (
              <div className="error-boundary-stack">
                <strong>Stack</strong>
                <pre>{stack}</pre>
              </div>
            )}
            {componentStack && (
              <div className="error-boundary-stack">
                <strong>Component stack</strong>
                <pre>{componentStack}</pre>
              </div>
            )}
          </div>
        )}
      </div>
    );
  }
}
