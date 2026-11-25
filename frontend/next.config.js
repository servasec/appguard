/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  allowedDevOrigins: ['appguard.servasec.local'],
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.INTERNAL_API_URL || 'http://backend:8080'}/:path*`,
      },
    ]
  },
  webpack(config, { dev }) {
    if (dev) {
      config.watchOptions = { ...config.watchOptions, poll: 1000 }
    }
    return config
  },
}

module.exports = nextConfig
