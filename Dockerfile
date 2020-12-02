FROM ruby:2.7.2-alpine3.12
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

CMD /app/bin/ssh_scan
