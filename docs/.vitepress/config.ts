import { defineConfig } from 'vitepress'

// Función para obtener la última versión de npm
async function getLatestVersion() {
  try {
    const response = await fetch('https://registry.npmjs.org/@nekzus/tokenly/latest')
    const data = await response.json()
    return data.version
  } catch (error) {
    console.warn('Failed to fetch latest version from npm:', error)
    return 'latest' // Fallback value
  }
}

// Configuración asíncrona
export default async () => {
  const version = await getLatestVersion()

  return defineConfig({
    base: '/tokenly/',
    title: "Tokenly",
    description: "Advanced JWT Token Management",

    head: [
      ['link', { rel: 'icon', type: 'image/svg+xml', href: '/tokenly/logo-light.svg', media: '(prefers-color-scheme: light)' }],
      ['link', { rel: 'icon', type: 'image/svg+xml', href: '/tokenly/logo-dark.svg', media: '(prefers-color-scheme: dark)' }],
      ['link', { rel: 'icon', type: 'image/png', href: '/tokenly/logo-light.png', media: '(prefers-color-scheme: light)' }],
      ['link', { rel: 'icon', type: 'image/png', href: '/tokenly/logo-dark.png', media: '(prefers-color-scheme: dark)' }],
      ['meta', { name: 'viewport', content: 'width=device-width, initial-scale=1.0' }],
      ['meta', { name: 'keywords', content: 'jwt, token, security, authentication, device fingerprinting' }],
      ['meta', { name: 'author', content: 'Nekzus' }],
      ['meta', { property: 'og:title', content: 'Tokenly - JWT Token Management' }],
      ['meta', { property: 'og:description', content: 'Advanced JWT Token Management with Device Fingerprinting' }],
      ['style', {}, `
        :root {
          --vp-layout-max-width: 1440px;
        }

        .VPDoc {
          max-width: 100%;
          width: 100%;
        }

        .VPDoc .container {
          max-width: var(--vp-layout-max-width);
          margin: 0 auto;
          padding: 0 24px;
        }

        @media (max-width: 768px) {
          .VPDoc .container {
            padding: 0 16px;
          }
        }

        @media (max-width: 480px) {
          .VPDoc .container {
            padding: 0 12px;
          }
        }

        .vp-code-group .tabs label {
          display: flex !important;
          align-items: center;
        }
        
        .vp-code-group .tabs label::before {
          margin-right: 6px;
          width: 16px;
          height: 16px;
          content: "";
          background-repeat: no-repeat;
          background-position: center;
          background-size: contain;
        }

        .vp-code-group .tabs label[data-title="npm"]::before {
          background-image: url("/tokenly/icons/npm.svg");
        }

        .vp-code-group .tabs label[data-title="pnpm"]::before {
          background-image: url("/tokenly/icons/pnpm.svg");
        }

        .vp-code-group .tabs label[data-title="yarn"]::before {
          background-image: url("/tokenly/icons/yarn.svg");
        }

        .vp-code-group .tabs label[data-title="bun"]::before {
          background-image: url("/tokenly/icons/bun.svg");
        }

        /* Responsive code blocks */
        .vp-code-group, .vp-code {
          max-width: 100%;
          overflow-x: auto;
        }

        /* Responsive tables */
        .vp-doc table {
          display: block;
          max-width: 100%;
          overflow-x: auto;
        }

        /* Responsive images */
        .vp-doc img {
          max-width: 100%;
          height: auto;
        }

        /* Buy Me a Coffee button styles */
        .VPSocialLinks .VPSocialLink[aria-label="Buy me a coffee"] svg {
          fill: #FFDD00;
          transition: fill 0.2s ease;
        }
        
        .VPSocialLinks .VPSocialLink[aria-label="Buy me a coffee"]:hover svg {
          fill: #FF813F;
        }
      `]
    ],

    themeConfig: {
      // https://vitepress.dev/reference/default-theme-config
      nav: [
        { text: 'Home', link: '/' },
        { text: 'Guide', link: '/guide/getting-started' },
        { text: 'API', link: '/api/tokenly' },
        { text: 'Security', link: '/guide/security' },
        {
          text: `${version}`,
          items: [
            {
              text: 'Changelog',
              link: 'https://github.com/nekzus/tokenly/blob/main/CHANGELOG.md'
            },
            {
              text: 'Contributing',
              link: 'https://github.com/nekzus/tokenly/blob/main/CONTRIBUTING.md'
            }
          ]
        }
      ],

      logo: {
        light: '/logo-light.svg',
        dark: '/logo-dark.svg',
        alt: 'Tokenly Logo'
      },

      sidebar: {
        '/guide/': [
          {
            text: 'Getting Started',
            items: [
              { text: 'What is Tokenly?', link: '/guide/what-is-tokenly' },
              { text: 'Getting Started', link: '/guide/getting-started' },
              { text: 'Security', link: '/guide/security' },
              { text: 'Type Safety', link: '/guide/type-safety' },
              { text: 'Advanced Concepts', link: '/guide/advanced-concepts' }
            ]
          }
        ],
        '/api/': [
          {
            text: 'API Reference',
            items: [
              { text: 'Tokenly Class', link: '/api/tokenly' },
              { text: 'Configuration', link: '/api/configuration' },
              { text: 'IP Helper', link: '/api/utils/ip-helper' },
              { text: 'Device Helper', link: '/api/utils/device-helper' },
            ]
          }
        ]
      },

      socialLinks: [
        { icon: 'github', link: 'https://github.com/nekzus/tokenly' },
        // { 
        //   icon: {
        //     svg: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M20.216 6.415l-.132-.666c-.119-.598-.388-1.163-1.001-1.379-.197-.069-.42-.098-.57-.241-.152-.143-.196-.366-.231-.572-.065-.378-.125-.756-.192-1.133-.057-.325-.102-.69-.25-.987-.195-.4-.597-.634-.996-.788a5.723 5.723 0 00-.626-.194c-1-.263-2.05-.36-3.077-.416a25.834 25.834 0 00-3.7.062c-.915.083-1.88.184-2.75.5-.318.116-.646.256-.888.501-.297.302-.393.77-.177 1.146.154.267.415.456.692.58.36.162.737.284 1.123.366 1.075.238 2.189.331 3.287.37 1.218.05 2.437.01 3.65-.118.299-.033.598-.073.896-.119.352-.054.578-.513.474-.834-.124-.383-.457-.531-.834-.473-.466.074-.96.108-1.382.146-1.177.08-2.358.082-3.536.006a22.228 22.228 0 01-1.157-.107c-.086-.01-.18-.025-.258-.036-.243-.036-.484-.08-.724-.13-.111-.027-.111-.185 0-.212h.005c.277-.06.557-.108.838-.147h.002c.131-.009.263-.032.394-.048a25.076 25.076 0 013.426-.12c.674.019 1.347.067 2.017.144l.228.031c.267.04.533.088.798.145.392.085.895.113 1.07.542.055.137.08.288.111.431l.319 1.484a.237.237 0 01-.199.284h-.003c-.037.006-.075.01-.112.015a36.704 36.704 0 01-4.743.295 37.059 37.059 0 01-4.699-.304c-.14-.017-.293-.042-.417-.06-.326-.048-.649-.108-.973-.161-.393-.065-.768-.032-1.123.161-.29.16-.527.404-.675.701-.154.316-.199.66-.267 1-.069.34-.176.707-.135 1.056.087.753.613 1.365 1.37 1.502a39.69 39.69 0 0011.343.376.483.483 0 01.535.53l-.071.697-1.018 9.907c-.041.41-.047.832-.125 1.237-.122.637-.553 1.028-1.182 1.171-.577.131-1.165.2-1.756.205-.656.004-1.31-.025-1.966-.022-.699.004-1.556-.06-2.095-.58-.475-.458-.54-1.174-.605-1.793l-.731-7.013-.322-3.094c-.037-.351-.286-.695-.678-.678-.336.015-.718.3-.678.679l.228 2.185.949 9.112c.147 1.344 1.174 2.068 2.446 2.272.742.12 1.503.144 2.257.156.966.016 1.942.053 2.892-.122 1.408-.258 2.465-1.198 2.616-2.657.34-3.332.683-6.663 1.024-9.995l.215-2.087a.484.484 0 01.39-.426c.402-.078.787-.212 1.074-.518.455-.488.546-1.124.385-1.766zm-1.478.772c-.145.137-.363.201-.578.233-2.416.359-4.866.54-7.308.46-1.748-.06-3.477-.254-5.207-.498-.17-.024-.353-.055-.47-.18-.22-.236-.111-.71-.054-.995.052-.26.152-.609.463-.646.484-.057 1.046.148 1.526.22.577.088 1.156.159 1.737.212 2.48.226 5.002.19 7.472-.14.45-.06.899-.13 1.345-.21.399-.072.84-.206 1.08.206.166.281.188.657.162.974a.544.544 0 01-.169.364zm-6.159 3.9c-.862.37-1.84.788-3.109.788a5.884 5.884 0 01-1.569-.217l.877 9.004c.065.78.717 1.38 1.5 1.38 0 0 1.243.065 1.658.065.447 0 1.786-.065 1.786-.065.783 0 1.435-.6 1.5-1.38l.94-9.95a3.996 3.996 0 00-1.322-.238c-.826 0-1.491.284-2.26.613z"/></svg>'
        //   },
        //   link: 'https://www.buymeacoffee.com/nekzus',
        //   ariaLabel: 'Buy me a coffee'
        // }
      ],

      footer: {
        message: 'Released under the MIT License.',
        copyright: `Copyright © 2025-present Nekzus`
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
      lineNumbers: false,
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
      },
      languageAlias: {
        env: "bash",
        ts: "typescript",
        js: "javascript",
        sh: "bash",
      }
    },

    vite: {
      publicDir: 'public',
    },

    rewrites: {
      'llms.txt': '/llms.txt',
      'llms-full.txt': '/llms-full.txt'
    }
  })
}
