# SMS Notifier Server Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create logs and auth directories
RUN mkdir -p logs auth

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash smsuser && \
    chown -R smsuser:smsuser /app
USER smsuser

# Expose port
EXPOSE 5000

# Health check (removed for development - not needed)

# Default environment variables
ENV HOST=0.0.0.0
ENV PORT=5000
ENV DEBUG=false
ENV LOG_LEVEL=INFO
ENV LOG_FILE=/app/logs/sms_notifier.log

# Run the application with Gunicorn
CMD ["gunicorn", "--config", "gunicorn.conf.py", "sms_notifier:create_app()"]
