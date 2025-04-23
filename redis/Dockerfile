FROM redis:7.4.2

RUN mkdir /app && chown redis:redis /app
RUN echo "vm.overcommit_memory = 1" > /etc/sysctl.conf

WORKDIR /app

USER redis

COPY --chown=redis:redis . .

CMD ["redis-server", "/app/redis.conf"]