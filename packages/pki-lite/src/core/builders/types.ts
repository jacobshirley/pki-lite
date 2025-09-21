export interface Builder<T> {
    build(): T
}

export interface AsyncBuilder<T> {
    build(): Promise<T>
}
