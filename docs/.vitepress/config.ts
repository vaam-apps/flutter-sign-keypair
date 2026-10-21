import { defineMd3Config } from "@vaam-apps/vitepress-md3/config";

// Served from GitHub Pages at /flutter-sign-keypair/. The docs workflow passes
// the path Pages reports in DOCS_BASE (empty on pull-request builds, hence
// `||` rather than `??`), so moving to a custom domain needs no change here.
const base = process.env.DOCS_BASE || "/flutter-sign-keypair/";
const repo = "https://github.com/vaam-apps/flutter-sign-keypair";

export default defineMd3Config({
  base,
  lang: "en",
  title: "flutter_sign_keypair",
  titleTemplate: ":title · flutter_sign_keypair",
  description:
    "Hardware-backed ECDSA P-256 (ES256) signing for device-bound authentication in Flutter, via AndroidKeyStore and the Apple Secure Enclave.",
  cleanUrls: true,
  lastUpdated: true,
  // A link to a page that does not exist fails the build.
  ignoreDeadLinks: false,
  head: [["link", { rel: "icon", type: "image/svg+xml", href: `${base}logo.svg` }]],

  themeConfig: {
    md3: {
      style: "expressive",
      // Flutter blue.
      seed: "#027dfd",
    },

    logo: "/logo.svg",

    nav: [
      { text: "Guide", link: "/guide/getting-started", activeMatch: "^/guide/(getting-started|how-it-works|verifying)" },
      { text: "API", link: "/guide/api", activeMatch: "^/guide/(api|errors)" },
      { text: "Platforms", link: "/guide/platforms", activeMatch: "^/guide/platforms" },
      {
        text: "More",
        items: [
          { text: "Testing & proof", link: "/guide/testing" },
          { text: "Migrating devices", link: "/guide/migration" },
          { text: "About", link: "/about" },
          { text: "Changelog", link: `${repo}/blob/main/CHANGELOG.md` },
          { text: "All vaam-apps docs", link: "https://vaam-apps.github.io/vitepress-md3/projects/" },
        ],
      },
    ],

    sidebar: [
      {
        text: "Introduction",
        items: [
          { text: "Overview", link: "/" },
          { text: "Getting started", link: "/guide/getting-started" },
        ],
      },
      {
        text: "Concepts",
        items: [
          { text: "How it works", link: "/guide/how-it-works" },
          { text: "Verifying signatures", link: "/guide/verifying" },
        ],
      },
      {
        text: "Reference",
        items: [
          { text: "API overview", link: "/guide/api" },
          { text: "Errors", link: "/guide/errors" },
          { text: "Platform notes & limitations", link: "/guide/platforms" },
        ],
      },
      {
        text: "Project",
        items: [
          { text: "Testing & proof", link: "/guide/testing" },
          { text: "Migrating devices", link: "/guide/migration" },
          { text: "About", link: "/about" },
          { text: "Changelog", link: `${repo}/blob/main/CHANGELOG.md` },
        ],
      },
    ],

    outline: { level: [2, 3] },
    search: { provider: "local" },
    socialLinks: [{ icon: "github", link: repo }],
    editLink: {
      pattern: `${repo}/edit/main/docs/:path`,
      text: "Edit this page on GitHub",
    },
    footer: {
      message: "Released under the MIT License. A fork of webank_secure_signer.",
      copyright: "Copyright © 2026 ADORSYS GIS · Copyright © 2026 Vaam",
    },
  },
});
