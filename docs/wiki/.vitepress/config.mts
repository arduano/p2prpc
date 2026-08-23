import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitepress';

const repository = process.env.GITHUB_REPOSITORY ?? 'arduano/p2prpc';
const repositoryUrl = `${process.env.GITHUB_SERVER_URL ?? 'https://github.com'}/${repository}`;
const repositoryOwner = repository.split('/').at(0) ?? 'arduano';
const repositoryName = repository.split('/').at(-1) ?? 'p2prpc';
const isUserSite = repositoryName.toLowerCase().endsWith('.github.io');
const inferredBase = process.env.GITHUB_ACTIONS === 'true' && !isUserSite
  ? `/${repositoryName}/`
  : '/';
const base = normalizeBase(process.env.DOCS_BASE ?? inferredBase);
const docsOrigin = (process.env.DOCS_ORIGIN ?? `https://${repositoryOwner}.github.io`).replace(/\/+$/, '');

function normalizeBase(value: string): string {
  if (value === '' || value === '/') return '/';
  return `/${value.replace(/^\/+|\/+$/g, '')}/`;
}

export default defineConfig({
  title: 'p2prpc',
  titleTemplate: ':title | p2prpc',
  description: 'Architecture and security documentation for typed peer-to-peer RPC and file transfer over Iroh QUIC.',
  lang: 'en',
  base,
  cleanUrls: true,
  srcExclude: ['_Sidebar.md'],
  lastUpdated: true,
  sitemap: {
    hostname: docsOrigin,
    transformItems: (items) => items.map((item) => ({
      ...item,
      url: `${base}${item.url.replace(/^\/+/, '')}`
    }))
  },
  head: [
    ['meta', { name: 'theme-color', content: '#2374e1' }],
    ['meta', { name: 'color-scheme', content: 'light dark' }],
    ['link', { rel: 'icon', type: 'image/svg+xml', href: `${base}favicon.svg` }]
  ],
  vite: {
    publicDir: fileURLToPath(new URL('./public', import.meta.url))
  },
  markdown: {
    headers: { level: [2, 3] },
    config(md) {
      const renderLinkOpen = md.renderer.rules.link_open
        ?? ((tokens, index, options, _environment, self) => self.renderToken(tokens, index, options));

      md.renderer.rules.link_open = (tokens, index, options, environment, self) => {
        const hrefIndex = tokens[index].attrIndex('href');
        if (hrefIndex >= 0 && tokens[index].attrs?.[hrefIndex]?.[1] === '../../SECURITY.md') {
          tokens[index].attrSet('href', `${repositoryUrl}/blob/main/SECURITY.md`);
        }
        return renderLinkOpen(tokens, index, options, environment, self);
      };
    }
  },
  themeConfig: {
    logo: '/mark.svg',
    siteTitle: 'p2prpc',
    nav: [
      { text: 'System model', link: '/Home' },
      { text: 'Security', link: '/Security-Model' },
      { text: 'Audit guide', link: '/Audit-Guide' },
      { text: 'Validation', link: '/Production-Validation' },
      { text: 'Repository', link: repositoryUrl }
    ],
    sidebar: [
      {
        text: 'Overview',
        items: [
          { text: 'System model', link: '/Home' },
          { text: 'Architecture', link: '/Architecture' },
          { text: 'Data model', link: '/Data-Model' },
          { text: 'Lifecycles', link: '/Lifecycles' }
        ]
      },
      {
        text: 'Security review',
        items: [
          { text: 'Security model', link: '/Security-Model' },
          { text: 'File transfers', link: '/File-Transfers' },
          { text: 'Audit guide', link: '/Audit-Guide' },
          { text: 'Production validation', link: '/Production-Validation' }
        ]
      }
    ],
    search: {
      provider: 'local',
      options: {
        detailedView: true
      }
    },
    outline: {
      level: [2, 3],
      label: 'On this page'
    },
    editLink: {
      pattern: `${repositoryUrl}/edit/main/docs/wiki/:path`,
      text: 'Edit this page on GitHub'
    },
    lastUpdated: {
      text: 'Last updated',
      formatOptions: {
        dateStyle: 'medium',
        timeStyle: 'short'
      }
    },
    docFooter: {
      prev: 'Previous',
      next: 'Next'
    },
    socialLinks: [
      { icon: 'github', link: repositoryUrl }
    ],
    externalLinkIcon: true,
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'p2prpc contributors'
    }
  }
});
