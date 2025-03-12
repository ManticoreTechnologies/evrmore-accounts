# Deployment Guide

This guide explains how to deploy Evrmore Accounts in a production environment.

## Deploying with Gunicorn

For production deployments, we recommend using [Gunicorn](https://gunicorn.org/) (Green Unicorn), a Python WSGI HTTP Server.

### Installation

First, ensure you have Gunicorn installed:

```bash
pip3 install gunicorn
```

Gunicorn is already included in the project's `requirements.txt`, so if you've installed the package dependencies, you should already have it.

### Basic Usage

The project includes a `wsgi.py` file that serves as the entry point for Gunicorn and a `run_gunicorn.sh` script that provides a convenient way to start the server with common configuration options.

To run the application using the provided script:

```bash
./run_gunicorn.sh
```

This script sets up Gunicorn with reasonable defaults:
- 4 worker processes
- 120 second timeout
- Binding to 0.0.0.0:5000
- Info-level logging

### Custom Configuration

You can customize the Gunicorn configuration by setting environment variables before running the script:

```bash
# Set custom values
export PORT=8000
export HOST=127.0.0.1
export WORKERS=2
export TIMEOUT=60
export LOG_LEVEL=debug

# Run with custom configuration
./run_gunicorn.sh
```

### Running Gunicorn Directly

If you prefer to run Gunicorn directly without the script:

```bash
gunicorn --bind 0.0.0.0:5000 --workers 4 wsgi:app
```

### Gunicorn Configuration Options

Here are some common Gunicorn options you might want to adjust:

| Option | Description | Default |
|--------|-------------|---------|
| `--workers` | Number of worker processes | 4 |
| `--timeout` | Worker timeout in seconds | 120 |
| `--bind` | Address to bind to | 0.0.0.0:5000 |
| `--log-level` | Log level (debug, info, warning, error, critical) | info |
| `--access-logfile` | Access log file | - (stdout) |
| `--error-logfile` | Error log file | - (stderr) |
| `--max-requests` | Maximum number of requests a worker will process before restarting | None |
| `--worker-class` | Worker class type (sync, eventlet, gevent, etc.) | sync |

For a complete list of options, refer to the [Gunicorn documentation](https://docs.gunicorn.org/en/stable/settings.html).

## Deployment with Docker

The project includes a Dockerfile that already uses Gunicorn for production deployments.

To build and run the Docker container:

```bash
# Build the Docker image
docker build -t evrmore-accounts .

# Run the container
docker run -p 5000:5000 evrmore-accounts
```

You can override the default settings by passing environment variables:

```bash
docker run -p 8000:8000 \
  -e PORT=8000 \
  -e WORKERS=2 \
  -e TIMEOUT=60 \
  -e JWT_SECRET=your_secure_secret \
  evrmore-accounts
```

## Deployment with Systemd

For deploying on Linux servers with systemd, you can create a service file:

```
[Unit]
Description=Evrmore Accounts Gunicorn Service
After=network.target

[Service]
User=evrmore
Group=evrmore
WorkingDirectory=/path/to/evrmore-accounts
Environment="PATH=/path/to/venv/bin"
Environment="JWT_SECRET=your_secure_secret"
ExecStart=/path/to/venv/bin/gunicorn --workers 4 --bind 0.0.0.0:5000 wsgi:app
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Save this to `/etc/systemd/system/evrmore-accounts.service`, then:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Start the service
sudo systemctl start evrmore-accounts

# Enable the service to start at boot
sudo systemctl enable evrmore-accounts
```

## Deployment with Nginx Reverse Proxy

In production, it's recommended to use Nginx as a reverse proxy in front of Gunicorn:

```
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

For HTTPS support, we recommend using Certbot to obtain SSL certificates:

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Obtain and configure SSL certificate
sudo certbot --nginx -d your-domain.com
```

## Performance Tuning

For high-traffic deployments, consider these optimizations:

1. **Adjust worker count**: A common formula is `2 * CPU cores + 1`
2. **Use worker classes**: For I/O bound applications, consider using gevent or eventlet
3. **Implement caching**: Add Redis or Memcached for caching
4. **Database connection pooling**: Optimize database connections
5. **Content Delivery Network (CDN)**: Use a CDN for static assets

## Health Checks

The application provides a health check endpoint at `/api/health` that returns the current status and version.

Use this for monitoring and load balancer health checks:

```bash
curl http://your-server.com/api/health
```

## Monitoring

For production deployments, consider setting up monitoring:

1. **Prometheus**: For metrics collection
2. **Grafana**: For dashboards and visualization
3. **ELK Stack**: For log aggregation and analysis
4. **Uptime monitoring**: Services like Uptime Robot or Pingdom

## Next Steps

- Review [security guidelines](../development/security.md) for production deployments
- Check [troubleshooting](../guides/troubleshooting.md) for common issues
- Explore [customization options](../guides/customization.md) for your deployment 