# BSim Analysis Portal - Static Web Application
FROM nginx:alpine

# Copy the static HTML file
COPY index.html /usr/share/nginx/html/

# Create custom nginx configuration for SPA
COPY nginx.conf /etc/nginx/nginx.conf

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:80/ || exit 1