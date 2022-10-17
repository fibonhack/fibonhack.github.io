FROM jekyll/jekyll:latest

WORKDIR /srv/jekyll
COPY Gemfile /srv/jekyll

RUN bundle install