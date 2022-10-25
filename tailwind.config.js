module.exports = {
  content: [
    './_includes/**/*.html',
    './assets/css/*.*',
    './assets/js/*.*',
    './_includes/*.html',
    './_layouts/**/*.html',
    './_layouts/*.html',
    './_posts/*.md',
    './*.html',
  ],
  theme: {
    extend: {},
  },
  variants: {},
  plugins: [
    require('@tailwindcss/typography'),
  ],
}
