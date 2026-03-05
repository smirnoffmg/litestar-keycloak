# Example app image: installs litestar-keycloak from the repo and runs the example.
# Build from repo root: docker build -f examples/Dockerfile .

FROM python:3.12-slim

WORKDIR /app

# Install the package and its dependencies from the repo
COPY pyproject.toml uv.lock ./
COPY src ./src/
RUN pip install --no-cache-dir .

# Copy example app
COPY examples/app ./examples/app/

ENV KEYCLOAK_SERVER_URL=http://localhost:8080
ENV REDIRECT_URI=http://localhost:8000/auth/callback

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/app/examples/app"]
