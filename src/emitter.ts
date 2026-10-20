/*
 * Copyright 2026 Bad Monkey, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * A small event emitter with the `on`, `once`, `off`, and `emit` names of
 * Node's, so the portable core needs no `node:events` (JS-P-04), and a
 * pluggable context store so the binder's current take works where
 * `AsyncLocalStorage` exists and degrades to a synchronous scope elsewhere.
 */

type Listener = (...args: any[]) => void;

export class Emitter {
  private readonly listeners = new Map<string, Listener[]>();

  on(event: string, listener: Listener): this {
    const list = this.listeners.get(event) ?? [];
    list.push(listener);
    this.listeners.set(event, list);
    return this;
  }

  addListener(event: string, listener: Listener): this {
    return this.on(event, listener);
  }

  once(event: string, listener: Listener): this {
    const wrapper: Listener = (...args) => {
      this.off(event, wrapper);
      listener(...args);
    };
    (wrapper as { original?: Listener }).original = listener;
    return this.on(event, wrapper);
  }

  off(event: string, listener: Listener): this {
    const list = this.listeners.get(event);
    if (list) {
      const index = list.findIndex((l) => l === listener
        || (l as { original?: Listener }).original === listener);
      if (index >= 0) {
        list.splice(index, 1);
      }
    }
    return this;
  }

  removeListener(event: string, listener: Listener): this {
    return this.off(event, listener);
  }

  removeAllListeners(event?: string): this {
    if (event === undefined) {
      this.listeners.clear();
    } else {
      this.listeners.delete(event);
    }
    return this;
  }

  /** Calls each listener in order; returns whether any listened. A listener's throw propagates, as in Node. */
  emit(event: string, ...args: unknown[]): boolean {
    const list = this.listeners.get(event);
    if (!list || list.length === 0) {
      return false;
    }
    for (const listener of [...list]) {
      listener(...args);
    }
    return true;
  }

  listenerCount(event: string): number {
    return this.listeners.get(event)?.length ?? 0;
  }
}

/** A value scoped to a call and everything it awaits, where the runtime can carry it. */
export interface ContextStore<T> {
  get(): T | undefined;
  run<R>(value: T, fn: () => R): R;
}

/** A synchronous scope: the value is visible until the call returns or first awaits. */
class StackStore<T> implements ContextStore<T> {
  private current: T | undefined;

  get(): T | undefined {
    return this.current;
  }

  run<R>(value: T, fn: () => R): R {
    const previous = this.current;
    this.current = value;
    try {
      return fn();
    } finally {
      this.current = previous;
    }
  }
}

type StoreFactory = <T>() => ContextStore<T>;

/** TC39 AsyncContext.Variable when the runtime has it, else the synchronous scope. */
let factory: StoreFactory = <T>(): ContextStore<T> => {
  const asyncContext = (globalThis as { AsyncContext?: { Variable: new () => ContextStore<T> } }).AsyncContext;
  return asyncContext ? new asyncContext.Variable() : new StackStore<T>();
};

/** Installs the factory that makes context stores (Node installs AsyncLocalStorage). */
export function installContextStores(make: StoreFactory): void {
  factory = make;
}

/** A context store that reads through to whichever implementation is installed when it is used. */
export function contextStore<T>(): ContextStore<T> {
  let made: ContextStore<T> | null = null;
  let madeBy: StoreFactory | null = null;
  const store = (): ContextStore<T> => {
    if (made === null || madeBy !== factory) {
      made = factory<T>();
      madeBy = factory;
    }
    return made;
  };
  return {
    get: () => store().get(),
    run: (value, fn) => store().run(value, fn),
  };
}
