FROM ruby
MAINTAINER Jonathan Claudius
ENV PROJECT=github.com/mozilla/ssh_scan

RUN mkdir /app
ADD . /app
WORKDIR /app

RUN gpg --keyserver hkp://keys.gnupg.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3
RUN curl -sSL https://get.rvm.io | bash -s stable --ruby
RUN gem install bundler
RUN bundle install
CMD /app/bin/ssh_scan
