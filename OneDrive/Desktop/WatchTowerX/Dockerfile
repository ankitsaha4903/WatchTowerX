# Lightweight Python Image
FROM python:3.10-slim

# Set Working Directory
WORKDIR /app

# Install Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Project Code
COPY . .

# Expose Port
EXPOSE 8000

# Start Command (Using shell form to ensure variable expansion if needed)
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
