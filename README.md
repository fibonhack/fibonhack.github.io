# fibonhack.github.io

> \> [fibonhack.it](https://fibonhack.it)

## Deployment

Pushes to `master` are built and deployed to GitHub Pages by `.github/workflows/build-and-deploy.yml`.

## Development

Requires Ruby (see `.ruby-version`) with Bundler, and Node.js.

```shell
bundle install
npm install
npm run dev     # serves on http://localhost:4000 with live CSS rebuild
npm run build   # outputs the site to _site/
```

Or, with Docker (only for local development, it's not used by the deployment):

```shell
docker compose up --build   # serves on http://localhost:4000
```

The docker environment mantains the incrementail rebuild of the pages like `npm run dev` does.
