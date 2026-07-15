FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY admin_panel /app/admin_panel

RUN useradd --uid 1000 --create-home app

USER app

EXPOSE 8765

HEALTHCHECK --interval=20s --timeout=5s --retries=3 --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=3)"

CMD ["python", "-m", "admin_panel.app", "--no-browser"]
