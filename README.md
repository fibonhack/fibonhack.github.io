## To build locally
`docker run --rm --volume="$PWD:/srv/jekyll" --env JEKYLL_ENV=development -p 4000:4000 jekyll/jekyll:3.8 jekyll serve --incremental`