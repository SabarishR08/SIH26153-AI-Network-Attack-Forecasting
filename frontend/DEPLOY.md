# NetWatch Frontend — Vercel Deployment Guide

## Quick Deploy

```bash
# 1. Install Vercel CLI
npm i -g vercel

# 2. Navigate to frontend directory
cd frontend

# 3. Deploy to Vercel
vercel

# 4. Deploy to production
vercel --prod
```

## Environment Variables

Set these in Vercel dashboard or via CLI:

| Variable | Description | Example |
|----------|-------------|---------|
| `API_BASE_URL` | Backend API URL | `https://netwatch-sih26153-api.onrender.com` |

## Manual Setup

1. Go to [vercel.com](https://vercel.com)
2. Import your GitHub repository
3. Set root directory to `frontend`
4. Framework preset: `Other`
5. Build command: `echo 'No build needed'`
6. Output directory: `public`
7. Add environment variable `API_BASE_URL`

## Architecture

```
frontend/
├── api/
│   └── proxy.js          # Serverless API proxy
├── public/
│   ├── index.html         # Main dashboard
│   └── static/
│       ├── css/main.css   # Styles
│       └── js/main.js     # Dashboard logic
├── vercel.json           # Vercel configuration
└── package.json          # Dependencies
```

## API Proxy

The `api/proxy.js` serverless function forwards `/api/*` requests to the Render backend, avoiding CORS issues in production.

## Custom Domain

1. Go to Vercel dashboard → Settings → Domains
2. Add your custom domain
3. Update DNS records as instructed
4. SSL is automatic

## Troubleshooting

- **API errors**: Check `API_BASE_URL` environment variable
- **CORS issues**: The proxy handles CORS automatically
- **Build errors**: This is a static site, no build step needed
