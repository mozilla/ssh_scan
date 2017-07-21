FROM ruby
MAINTAINER Jonathan Claudius
RUN mkdir /app
COPY . /app
WORKDIR /app
RUN apt-get update && \
    apt-get install -y tor proxychains && \
    gem install bundler && \
    bundle install
