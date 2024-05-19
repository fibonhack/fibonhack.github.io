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
    './_main/*.md',
  ],
  theme: {
    extend: {},
    container: {
      // you can configure the container to be centered
      center: true,

      // or have default horizontal padding
      padding: '1rem',

      // default breakpoints but with 40px removed
      screens: {
        sm: '600px',
        md: '728px',
        lg: '984px',
        // xl: '1240px',
        // '2xl': '1496px',
      },
    },
  },
  variants: {},
  plugins: [
    require('@tailwindcss/typography'),
  ],
}
