FROM ruby:alpine
MAINTAINER Jonathan Claudius
ENV PROJECT=github.com/mozilla/ssh_scan

RUN mkdir /app
ADD . /app
WORKDIR /app

# required for ssh-keyscan
RUN apk --update add openssh-client

RUN apk --update add --virtual build-dependencies ruby-dev build-base && \
    gem install bundler && \
    bundle install && \
    apk del build-dependencies && \
    rm -rf /var/cache/apk/*

CMD /app/bin/ssh_scan
