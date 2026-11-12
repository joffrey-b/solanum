// The in-app dialogs (confirm, overwrite, text prompt) share one queue: only
// the oldest open request is shown, and answering it shows the next. A second
// request while one is open waits instead of replacing it, so every caller's
// promise is answered (F-048). Kept apart from React so it can be tested.

export interface Queued<E> {
  id: number;
  entry: E;
}

export class DialogQueue<E> {
  private items: { id: number; entry: E; resolve: (value: any) => void }[] = [];
  private nextId = 1;

  constructor(private readonly onChange: () => void) {}

  /** Adds a request; resolves with the value its dialog is answered with. */
  push<T>(entry: E): Promise<T> {
    return new Promise<T>((resolve) => {
      this.items.push({ id: this.nextId++, entry, resolve });
      this.onChange();
    });
  }

  /** The request on screen, if any. */
  head(): Queued<E> | null {
    const first = this.items[0];
    return first ? { id: first.id, entry: first.entry } : null;
  }

  get size(): number {
    return this.items.length;
  }

  /** Answers request `id`. A request already answered is ignored (a click and
   *  a key landing together). */
  settle(id: number, value: unknown): void {
    const i = this.items.findIndex((x) => x.id === id);
    if (i < 0) return;
    const [item] = this.items.splice(i, 1);
    item.resolve(value);
    this.onChange();
  }
}
