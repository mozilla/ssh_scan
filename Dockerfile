FROM ruby:3.0.1-alpine3.13
MAINTAINER Jonathan Claudius
ENV PROJECT=github.com/mozilla/ssh_scan

WORKDIR /app
ADD . /app

# required for ssh-keyscan
RUN apk --update add openssh-client

ENV GEM_HOME /usr/local/bundle/ruby/$RUBY_VERSION

RUN apk --update add --virtual build-dependencies build-base && \
    bundle install && \
    apk del build-dependencies build-base && \
    rm -rf /var/cache/apk/*