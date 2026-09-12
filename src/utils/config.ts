/**
 * CIPHER AI - Global Configuration & Environment Detection
 */

// Explicit Demo Mode flag. Controlled via VITE_DEMO_MODE in .env.
// Default in production / customer environments must always be false.
export const IS_DEMO_MODE = import.meta.env.VITE_DEMO_MODE === 'true';
