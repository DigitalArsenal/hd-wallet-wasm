export class SessionGenerationGuard {
  #generation = 0;

  begin() {
    this.#generation += 1;
    return this.#generation;
  }

  capture() {
    return this.#generation;
  }

  invalidate() {
    this.#generation += 1;
    return this.#generation;
  }

  isCurrent(sessionGeneration) {
    return Number.isSafeInteger(sessionGeneration)
      && sessionGeneration === this.#generation;
  }

  async commitIfCurrent(sessionGeneration, pendingValue, commit) {
    const value = await pendingValue;
    if (!this.isCurrent(sessionGeneration)) return false;
    commit(value);
    return true;
  }
}
