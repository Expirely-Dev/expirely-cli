import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://bycavii.github.io',
  base: '/expirely-cli',
  integrations: [
    starlight({
      title: 'expirely',
      description: 'Find every TLS certificate you serve and when it expires.',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/bycavii/expirely-cli' },
      ],
      editLink: {
        baseUrl: 'https://github.com/bycavii/expirely-cli/edit/main/docs/',
      },
      sidebar: [
        {
          label: 'Getting started',
          items: [
            { label: 'Introduction', slug: 'getting-started/introduction' },
            { label: 'Install', slug: 'getting-started/install' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Scan targets', slug: 'guides/targets' },
            { label: 'Gate CI and alert from cron', slug: 'guides/ci' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Command line', slug: 'reference/cli' },
            { label: 'JSON output', slug: 'reference/json' },
            { label: 'Exit and error codes', slug: 'reference/codes' },
          ],
        },
      ],
    }),
  ],
});
