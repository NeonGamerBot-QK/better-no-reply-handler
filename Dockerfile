# Dockerfile for the Node.js mail handler application
FROM node:22-alpine

# Install curl for healthcheck
RUN apk add --no-cache curl

WORKDIR /app

# Copy package files first for better layer caching
COPY package.json pnpm-lock.yaml ./

# Install pnpm and dependencies
RUN corepack enable && pnpm install --frozen-lockfile --prod

# Copy application source
COPY src ./src

# Expose the application port and SMTP port
EXPOSE 3000 2525

# Run the application
CMD ["node", "src/index.js"]
