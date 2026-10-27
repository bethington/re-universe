# GitHub Mining Service - Multi-stage Docker build
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download NLTK data
# nltk 3.9 renamed the 'punkt' tokenizer resource to 'punkt_tab'. Downloading
# 'punkt' still reports success but does not provide the resource that
# nltk.word_tokenize() actually looks up, so the download must use the new
# name. 'punkt' is kept for compatibility with nltk < 3.9 consumers.
RUN python -c "import nltk; nltk.download('punkt_tab'); nltk.download('punkt'); nltk.download('vader_lexicon'); nltk.download('stopwords')"

# Copy application code
COPY . .

# Expose port
EXPOSE 8094

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8094/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8094"]