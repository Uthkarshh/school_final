FROM python:3.12.3-slim

WORKDIR /app

# Install required packages
RUN apt-get update && apt-get install -y \
    postgresql-client \
    gcc \
    python3-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port for the Flask app
EXPOSE 5000

# Add this before CMD
COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

# Replace CMD with ENTRYPOINT
ENTRYPOINT ["./docker-entrypoint.sh"]

# Command to run the application
CMD ["python", "run.py"]
