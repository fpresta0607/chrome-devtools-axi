/**
 * Opt-in idle shutdown for the detached bridge.
 *
 * See README.md#idle-timeout for configuration and activity semantics.
 * Authentication and activity classification belong to createBridgeServer
 * and isIdleActivity in src/bridge.ts.
 */

export const IDLE_TIMEOUT_ENV = "CHROME_DEVTOOLS_AXI_IDLE_TIMEOUT_MS";

/** Floor for a configured timeout, matching the bridge startup deadline's. */
export const MIN_IDLE_TIMEOUT_MS = 1_000;

/**
 * The configured idle timeout, or 0 when idle shutdown is off. Unset, blank,
 * `0`, and anything that is not a plain non-negative integer leave it off, so
 * a unit typo such as `30m` can never turn into a 30ms (or 1s) timeout. A
 * positive value below {@link MIN_IDLE_TIMEOUT_MS} is raised to it.
 */
export function resolveIdleTimeoutMs(
  raw: string | undefined = process.env[IDLE_TIMEOUT_ENV],
): number {
  const value = raw?.trim();
  if (!value || !/^\d+$/.test(value)) return 0;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed === 0) return 0;
  return Math.max(parsed, MIN_IDLE_TIMEOUT_MS);
}

const MAX_TIMER_DELAY_MS = 2 ** 31 - 1;

export interface IdleTracker {
  /**
   * Mark a request in flight; no idle shutdown happens while any is. Call the
   * returned function once when it ends, with whether it counts as activity.
   */
  begin(): (activity: boolean) => void;
}

/**
 * Call `onIdle` once, after `timeoutMs` pass with no activity and nothing in
 * flight. The countdown starts at creation. A request in flight across the
 * deadline defers it until that request ends; a non-activity request then
 * expires it immediately, an activity request restarts the full countdown.
 */
export function createIdleTracker(
  timeoutMs: number,
  onIdle: () => void,
): IdleTracker {
  let lastActivity = Date.now();
  let inFlight = 0;
  let idled = false;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const schedule = () => {
    clearTimeout(timer);
    timer = undefined;
    if (idled || inFlight > 0) return;
    const remaining = lastActivity + timeoutMs - Date.now();
    // setTimeout fires at once for a delay above its 32-bit ceiling, so a
    // longer timeout waits in capped steps and re-checks the deadline.
    timer = setTimeout(
      () => {
        timer = undefined;
        if (lastActivity + timeoutMs > Date.now()) {
          schedule();
          return;
        }
        idled = true;
        onIdle();
      },
      Math.min(Math.max(0, remaining), MAX_TIMER_DELAY_MS),
    );
    // The HTTP server keeps the bridge alive; this timer must never be the
    // only thing that does.
    timer.unref();
  };

  schedule();

  return {
    begin() {
      inFlight++;
      clearTimeout(timer);
      timer = undefined;
      let ended = false;
      return (activity) => {
        if (ended) return;
        ended = true;
        inFlight--;
        if (activity) lastActivity = Date.now();
        schedule();
      };
    },
  };
}
