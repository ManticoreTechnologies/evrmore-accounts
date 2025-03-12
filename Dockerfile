FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=5000
ENV HOST=0.0.0.0
ENV WORKERS=4
ENV TIMEOUT=120
ENV LOG_LEVEL=info

# Create a non-root user for security
RUN adduser --disabled-password --gecos "" appuser
RUN chown -R appuser:appuser /app
USER appuser

# Make run script executable
RUN chmod +x run_gunicorn.sh

# Run the application with Gunicorn
CMD ["./run_gunicorn.sh"] 