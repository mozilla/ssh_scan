FROM ruby:latest
MAINTAINER Jonathan Claudius
COPY . /app
RUN cd /app && \
    gem install bundler && \
    bundle install