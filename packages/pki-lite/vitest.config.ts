import { defineConfig } from 'vitest/config'
import { playwright } from '@vitest/browser-playwright'

export default defineConfig({
    test: {
        globalTeardown: ['./test/globalTeardown.ts'],
        projects: [
            {
                test: {
                    name: 'node',
                    environment: 'node',
                    exclude: ['node_modules'],
                },
            },
            {
                test: {
                    name: 'browser',
                    include: ['**/*.(test|spec).ts'],
                    exclude: ['test/node/**', 'node_modules'],
                    browser: {
                        // Disable CORS to test the timestamp request example
                        provider: playwright({
                            contextOptions: {
                                extraHTTPHeaders: {
                                    'Content-Type':
                                        'application/timestamp-query',
                                },
                            },
                            launchOptions: {
                                args: ['--disable-web-security'],
                            },
                        }),
                        enabled: true,
                        headless: true,
                        screenshotFailures: false,
                        instances: [{ browser: 'chromium' }],
                    },
                },
            },
        ],
    },
})
