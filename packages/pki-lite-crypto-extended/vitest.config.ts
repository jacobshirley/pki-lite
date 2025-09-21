import { defineConfig } from 'vitest/config'
import { playwright } from '@vitest/browser/providers/playwright'

export default defineConfig({
    test: {
        browser: {
            provider: playwright(),
            enabled: true,
            headless: true,
            screenshotFailures: false,
            // at least one instance is required
            instances: [{ browser: 'chromium' }],
        },
    },
})
