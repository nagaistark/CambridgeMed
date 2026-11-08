const pending = new Set<Promise<void>>();

/* Awaits the task purely to learn when it settles, then forgets it. A rejection is swallowed here on purpose: this tracker only observes settlement, and the caller owns error handling. Because this function can never reject, `void release(...)` can never produce an unhandled rejection. */
async function release(task: Promise<void>): Promise<void> {
   try {
      await task;
   } catch {
      /* Deliberately empty. */
   } finally {
      pending.delete(task);
   }
}

export function trackBackgroundTask(task: Promise<void>): void {
   pending.add(task);
   void release(task);
}

export async function drainBackgroundTasks(): Promise<void> {
   while (pending.size > 0) {
      await Promise.allSettled([...pending]);
   }
}
