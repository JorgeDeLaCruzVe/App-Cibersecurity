FROM python:3.12-slim
WORKDIR /app
COPY server.py index.html ./
RUN useradd -r -u 10001 securityai
USER securityai
ENV PORT=10000
EXPOSE 10000
CMD ["python", "server.py"]
