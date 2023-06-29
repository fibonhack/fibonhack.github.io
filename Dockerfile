FROM jekyll/jekyll:4.2.2

WORKDIR /srv/jekyll
COPY Gemfile /srv/jekyll

RUN bundle install
RUN export PATH="$(yarn global bin):$PATH"
