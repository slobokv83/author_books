FROM python:3.8-alpine

RUN mkdir ./usr/src/app

WORKDIR ./usr/src/app
ENV FLASK_APP=author_app.py
ENV FLASK_RUN_HOST=0.0.0.0

RUN python -m venv venv
RUN pip install --upgrade pip
# RUN apk update && apk add libressl-dev postgresql-dev libffi-dev gcc musl-dev python3-dev

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
# RUN pip install gunicorn

COPY  . .
# COPY boot.sh boot.sh
# RUN chmod a+x ./app/boot.sh

# ENTRYPOINT ["./boot.sh"]
# RUN source venv/bin/activate

# RUN chmod 777 .env .flaskenv .postgresenv

# CMD ["python", "-u", "author_app.py"]