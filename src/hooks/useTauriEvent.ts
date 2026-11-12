import { useEffect, useRef } from "react";
import { listen, type Event } from "@tauri-apps/api/event";
import { subscribe } from "../util/tauriEvents";

/**
 * Listens to the app event `name` while the component is mounted (F-052):
 * removed on unmount or when `name` changes, even if that happens before the
 * registration finished. `null` subscribes to nothing. The latest `handler`
 * is called, so it may use the current props and state.
 */
export function useTauriEvent<T>(name: string | null, handler: (event: Event<T>) => void): void {
  const handlerRef = useRef(handler);
  handlerRef.current = handler;
  useEffect(() => {
    if (!name) return;
    return subscribe<Event<T>>((n, h) => listen<T>(n, h), name, (event) => handlerRef.current(event));
  }, [name]);
}
