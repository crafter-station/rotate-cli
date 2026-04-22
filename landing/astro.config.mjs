// @ts-check
import { fileURLToPath } from "node:url";
import { defineConfig } from "astro/config";
import vercel from "@astrojs/vercel";
import tailwind from "@tailwindcss/vite";

import react from "@astrojs/react";

export default defineConfig({
  output: "static",
  site: "https://rotate-cli.crafter.run",

  adapter: vercel({
    webAnalytics: { enabled: true },
  }),

  vite: {
    plugins: [tailwind()],
    resolve: {
      alias: {
        src: fileURLToPath(new URL("./src", import.meta.url)),
      },
    },
  },

  integrations: [react()],
});