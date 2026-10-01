FROM python:3.11-alpine

WORKDIR /app

# Install dependencies needed for compiling cryptography/ldap if wheel is not available
RUN apk add --no-cache gcc musl-dev libffi-dev openldap-dev

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENV ENV="/etc/profile"
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

ENTRYPOINT ["/docker-entrypoint.sh"]
