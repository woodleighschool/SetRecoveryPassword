FROM ghcr.io/linuxserver/baseimage-ubuntu:jammy

# set version label
LABEL maintainer="ozpinbeacon"

RUN \
	echo "**** install runtime packages ****" && \
	apt-get update && \
	apt-get -y install sqlite3 python3 python3-venv && \
	mkdir /venv && \
	python3 -m venv /venv && \
	. /venv/bin/activate && \
	pip install onepassword-sdk --trusted-host pypi.python.org --trusted-host pypi.org --trusted-host files.pythonhosted.org && \
	pip install apscheduler --trusted-host pypi.python.org --trusted-host pypi.org --trusted-host files.pythonhosted.org && \
	pip install requests --trusted-host pypi.python.org --trusted-host pypi.org --trusted-host files.pythonhosted.org

# copy local files
COPY root/ /

# ports and volumes
VOLUME /config