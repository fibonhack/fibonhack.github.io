# Local development only: the deployment is done by .github/workflows/build-and-deploy.yml
# Usage: docker compose up --build

FROM node:24-slim AS node

FROM ruby:3.4

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# node_modules are installed outside /site so they are not hidden by the bind mount,
# node finds them in /node_modules by walking up from /site
WORKDIR /opt/deps
COPY package.json package-lock.json ./
RUN npm ci && ln -s /opt/deps/node_modules /node_modules
ENV PATH=/node_modules/.bin:$PATH

# gems are installed in /usr/local/bundle by the ruby image
WORKDIR /site
COPY Gemfile Gemfile.lock ./
RUN bundle install

EXPOSE 4000

# same as `npm run dev`, but the build output goes to /tmp/site
# so the container doesn't leave root-owned files in the bind-mounted project folder
CMD exec concurrently --kill-others \
    "JEKYLL_ENV=production bundle exec jekyll serve --force-polling --host 0.0.0.0 --destination /tmp/site --disable-disk-cache" \
    "postcss assets/css/style.css --output /tmp/site/assets/css/style.css --watch --poll"
