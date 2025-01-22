import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: "Tokenly",
  description: "Advanced JWT Token Management with Device Fingerprinting",
  
  head: [
    ['link', { rel: 'icon', href: '/favicon.ico' }],
    ['meta', { name: 'keywords', content: 'jwt, token, security, authentication, device fingerprinting' }],
    ['meta', { name: 'author', content: 'Nekzus' }],
    ['meta', { property: 'og:title', content: 'Tokenly - JWT Token Management' }],
    ['meta', { property: 'og:description', content: 'Advanced JWT Token Management with Device Fingerprinting' }],
  ],

  themeConfig: {
    // https://vitepress.dev/reference/default-theme-config
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'API', link: '/api/tokenly' },
      { text: 'Security', link: '/guide/security' }
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Introduction',
          collapsed: false,
          items: [
            { text: 'Getting Started', link: '/guide/getting-started' },
            { text: 'Security Guide', link: '/guide/security' }
          ]
        },
        {
          text: 'Advanced Concepts',
          collapsed: false,
          items: [
            { text: 'Device Fingerprinting', link: '/guide/fingerprinting' },
            { text: 'Token Rotation', link: '/guide/token-rotation' },
            { text: 'Error Handling', link: '/guide/error-handling' },
            { text: 'Best Practices', link: '/guide/best-practices' }
          ]
        }
      ],
      '/api/': [
        {
          text: 'Core',
          items: [
            { text: 'Tokenly', link: '/api/tokenly' },
            { text: 'Configuration', link: '/api/configuration' }
          ]
        },
        {
          text: 'Utilities',
          items: [
            { text: 'IP Helper', link: '/api/utils/ip-helper' },
            { text: 'Device Helper', link: '/api/utils/device-helper' }
          ]
        }
      ]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/nekzus/tokenly' },
      { icon: 'bluesky', link: 'https://bsky.app/profile/nekzus.dev' }
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: `Copyright © ${new Date().getFullYear()} Nekzus`
    },

    search: {
      provider: 'local',
      options: {
        detailedView: true,
        translations: {
          button: {
            buttonText: 'Search',
            buttonAriaLabel: 'Search documentation'
          },
          modal: {
            displayDetails: 'Display detailed results',
            noResultsText: 'No results found',
            resetButtonTitle: 'Clear search',
            footer: {
              selectText: 'to select',
              navigateText: 'to navigate',
              closeText: 'to close'
            }
          }
        }
      }
    },

    outline: {
      level: [2, 3],
      label: 'On this page'
    },

    docFooter: {
      prev: 'Previous page',
      next: 'Next page'
    },

    lastUpdated: {
      text: 'Last updated',
      formatOptions: {
        dateStyle: 'full',
        timeStyle: 'short'
      }
    }
  },

  markdown: {
    lineNumbers: true,
    theme: {
      light: 'github-light',
      dark: 'github-dark'
    },
    container: {
      tipLabel: 'TIP',
      warningLabel: 'WARNING',
      dangerLabel: 'DANGER',
      infoLabel: 'INFO',
      detailsLabel: 'Details'
    },
    headers: {
      level: [2, 3, 4]
    }
  }
})
