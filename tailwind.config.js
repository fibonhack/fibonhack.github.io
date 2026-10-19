module.exports = {
  content: [
    './*.{html,md}',
    './_includes/**/*.html',
    './_layouts/**/*.html',
    './_main/**/*.{html,md}',
    './_writeups/**/*.{html,md}',
    './_ourposts/**/*.{html,md}',
    './_ourevents/**/*.{html,md}',
    './_authors/**/*.{html,md}',
    './_logo/**/*.{html,md}',
    './assets/css/*.css',
    './assets/js/*.js',
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
