FROM ruby
MAINTAINER Jonathan Claudius
ENV PROJECT=github.com/mozilla/ssh_scan

RUN mkdir /app
ADD . /app
WORKDIR /app

RUN gem install bundler
RUN bundle install
CMD /app/bin/ssh_scan
