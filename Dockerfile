FROM php:8.2-cli
COPY api.php /app/api.php
WORKDIR /app
EXPOSE 3000
CMD ["php", "-S", "0.0.0.0:3000", "api.php"]
