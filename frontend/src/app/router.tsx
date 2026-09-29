import { useEffect, useRef } from 'react';
import { createBrowserRouter, RouterProvider, useLocation } from 'react-router-dom';

/**
 * Live region that announces route transitions to assistive technology.
 *
 * The region is rendered once at the router root so that every navigation
 * (including interrupted/aborted transitions) produces a single, deterministic
 * announcement without stranding focus on a removed element.
 */
function RouteAnnouncer() {
  const location = useLocation();
  const [], setMessage] = useState('');
  const firstRender = useRef(true);

  useEffect(() => {
    // Skip the initial mount so we don't announce the landing route.
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }

    const title = document.title ? `${document.title} ` : '';
    const path = `${location.pathname}${location.search}${location.hash}`;
    setMessage(`${title}Navigated to ${path}`);
  }, [location.pathname, location.search, location.hash]);

  return (
    <div
      aria-live="polite"
      aria-atomic="true"
      role="status"
      style={{
        position: 'absolute',
        width: 1,
        height: 1,
        padding: 0,
        margin: -1,
        overflow: 'hidden',
        clip: 'rect(0, 0, 0, 0)',
        whiteSpace: 'nowrap',
        border: 0,
      }}
    >
      {message}
    </div>
  );
}

/**
 * Moves focus to the main content region after a route transition so keyboard
 * and screen-reader users are not left on a stale element. If the route
 * transition is interrupted (a new navigation happens before the effect
 * settles), the cleanup cancels the pending focus move and the next effect run
 * handles the latest location instead.
 */
function RouteFocusManager() {
  const location = useLocation();

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const main =
        document.querySelector<HTMLElement>('[data-route-focus]') ??
        document.querySelector<HTMLElement>('main');

      if (!main) {
        return;
      }

      if (!main.hasAttribute('tabindex')) {
        main.setAttribute('tabindex', '-1');
      }

      // Only steal focus if it is not already inside an active dialog.
      const activeDialog = document.querySelector<HTMLElement>(
        '[role="dialog"][aria-modal="true"], [role="alertdialog"][aria-modal="true"]',
      );
      if (activeDialog && activeDialog.contains(document.activeElement)) {
        return;
      }

      main.focus({ preventScroll: true });
    });

    return () => window.cancelAnimationFrame(frame);
  }, [location.pathname, location.search, location.hash]);

  return null;
}

export const router = createBrowserRouter([
  {
    path: '/*',
    element: (
      <>
        <RouteAnnouncer />
        <RouteFocusManager />
      </>
    ),
  },
]);

export default router;
