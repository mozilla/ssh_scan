#!/bin/bash

service nginx stop && letsencrypt renew && service nginx start
