import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  message?: string;
}

/** Catches rendering errors and shows a fallback UI instead of a blank screen. */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(error: unknown): State {
    return {
      hasError: true,
      message: error instanceof Error ? error.message : String(error),
    };
  }

  componentDidCatch(error: unknown, info: unknown) {
    // Surface the error to the console for debugging without crashing the app.
    console.error("ErrorBoundary caught an error:", error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback ?? (
          <div className="rounded-lg border border-destructive/40 bg-destructive/5 p-6">
            <h2 className="text-base font-semibold text-destructive">
              Something went wrong
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              {this.state.message ?? "An unexpected error occurred."}
            </p>
            <button
              type="button"
              onClick={() => this.setState({ hasError: false, message: undefined })}
              className="mt-3 rounded-md border bg-background px-3 py-1.5 text-sm"
            >
              Try again
            </button>
          </div>
        )
      );
    }
    return this.props.children;
  }
}
