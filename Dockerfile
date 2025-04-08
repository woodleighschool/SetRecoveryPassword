FROM ghcr.io/linuxserver/baseimage-alpine:3.20

# set version label
LABEL maintainer="ozpinbeacon"

RUN \
  echo "**** install runtime packages ****" && \
  apk add --no-cache \
	sqlite \
    py3-apscheduler \
	py3-requests \ 
	python3

# copy local files
COPY root/ /

# ports and volumes
VOLUME /config