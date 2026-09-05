# Pin an internally reviewed image digest for a production deployment.
FROM python:3.13-slim
RUN groupadd --gid 10001 opentapeout && useradd --uid 10001 --gid 10001 --create-home opentapeout
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir '.[web]'
USER 10001:10001
WORKDIR /workspace
EXPOSE 8080
# OPENTAPEOUT_API_TOKEN (32+ chars) is required for non-loopback binding.
# Mount an existing workspace plus read-only protected policy/trust, and put TLS in front.
ENTRYPOINT ["opentapeout", "--root", "/workspace"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
