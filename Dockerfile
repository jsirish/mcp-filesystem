FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py .

# Create default allowed directories
RUN mkdir -p /workspace /tmp

# Run the application
CMD ["python", "main.py"]