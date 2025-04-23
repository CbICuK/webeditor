FROM python:3.13.3-alpine3.21

ARG https_proxy=http://proxy:3128 \
    http_proxy=http://proxy:3128 \
    UNAME=appuser \
    UID=1111 \
    GID=1111



ENV PATH="/home/$UNAME/.local/bin:$PATH" \
    FLASK_APP="app.py" \
    FLASK_ENV="production" \
    PYTHONUNBUFFERED=1


RUN addgroup --gid $GID $UNAME && \
    adduser --disabled-password --ingroup "$UNAME" --uid $UID $UNAME && \
    mkdir /data && mkdir /db && \
    chown $UID:$GID /data && chown $UID:$GID /db

VOLUME ["/data", \
        "/db"]    

USER $UNAME

WORKDIR /app

COPY --chown=$UID:$GID requirements.txt .

RUN pip3 install --no-cache-dir -r requirements.txt --user

COPY --chown=$UID:$GID . .

CMD ["flask", "run", "--host=0.0.0.0", "--port=6700", "--key=webeditor.key", "--cert=webeditor.crt", "--debug"]
#CMD ["gunicorn", "-b", "0.0.0.0:6700", "--keyfile=webeditor.key", "--certfile=webeditor.crt", "app:app"]