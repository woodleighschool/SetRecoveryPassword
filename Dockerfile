# syntax=docker/dockerfile:1

FROM docker.io/library/python:3.14-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV DB_PATH="/config/state.db"

USER root

COPY requirements.txt pyproject.toml setrecoverypassword.py /app/
WORKDIR /app

RUN \
	apt-get update \
	&& \
	apt-get install -y --no-install-recommends --no-install-suggests \
		sqlite3 \
	&& \
	pip3 install --no-cache-dir -r \
		requirements.txt \
	&& \
	pip3 install --no-cache-dir \
		. \
	\
	&& apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
	&& apt-get autoremove -y \
	&& apt-get clean

USER nobody:nogroup

CMD ["setrecoverypassword"]