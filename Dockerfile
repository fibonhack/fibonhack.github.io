FROM node:22 AS node_modules
WORKDIR /tmp

COPY package.json package-lock.json ./
RUN npm install


# two stages so node_modules and gems are independent of each other
FROM node:22 AS runner

WORKDIR /site

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
	ruby-dev \
    && rm -rf /var/lib/apt/lists/*

# get jekyll
RUN gem install jekyll bundler && gem cleanup

COPY Gemfile Gemfile.lock ./
RUN bundle install

COPY --from=node_modules /tmp/node_modules ./node_modules

COPY . .

EXPOSE 4000

CMD ["npm", "run", "dev"]
# to build run npm run build and copy the _site folder