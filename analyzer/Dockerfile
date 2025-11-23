FROM python:3.10-slim

# Install YARA library and dependencies
RUN apt-get update && apt-get install -y \
    libyara-dev \
    yara \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download and extract YARA-Forge rules
RUN mkdir -p yara-rules && \
    cd yara-rules && \
    wget -q https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip && \
    unzip -q yara-forge-rules-full.zip && \
    rm yara-forge-rules-full.zip

# Copy analyzer source
COPY src ./src

CMD ["python", "src/analyzer.py"]
