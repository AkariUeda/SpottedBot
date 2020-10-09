FROM python:3.6.12-slim

ENV PYTHONUNBUFFERED=1

RUN mkdir /app

WORKDIR /app

RUN apt update && apt-get install git -y

COPY requirements.txt /app/

RUN pip install -r requirements.txt

COPY . /app/

COPY ./docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod a+x /docker-entrypoint.sh

ENTRYPOINT [ "/docker-entrypoint.sh" ]

CMD gunicorn -b 0.0.0.0:8000 project.wsgi --error-logfile - --access-logfile - --capture-output
