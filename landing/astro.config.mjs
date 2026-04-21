// @ts-check
import { defineConfig } from "astro/config";
import vercel from "@astrojs/vercel";
import tailwind from "@tailwindcss/vite";

export default defineConfig({
  output: "static",
  site: "https://rotate-cli.crafter.run",
  adapter: vercel({
    webAnalytics: { enabled: true },
  }),
  vite: {
    plugins: [tailwind()],
  },
});
