FROM nginx:1.28-alpine
COPY nginx.conf.template /etc/nginx/templates/nginx.conf.template
ENV NGINX_ENVSUBST_OUTPUT_DIR="/etc/nginx"
EXPOSE 80
