export default function globalTeardown() {
    // Vitest browser mode (Playwright) has a known issue where the process
    // hangs after all tests complete in CI. Force exit after a short delay
    // to allow final output to flush.
    setTimeout(() => {
        process.exit(0)
    }, 5000)
}
