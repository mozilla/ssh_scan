---
layout: post
title:  "First Meeting with MWoS Project Team"
date:   2016-10-20 12:00:00
author: claudijd
---

Today we conducted our first weekly meeting with the Mozilla Winter of Security (MWoS) project team focused on improving the feature set and scalability of [ssh_scan](https://github.com/mozilla/ssh_scan).  If you're not familiar with MWoS, it's a play on [Google's Summer of Code (GSoC)](https://developers.google.com/open-source/gsoc/) program and you can find more details about MWoS [here](https://wiki.mozilla.org/Security/Automation/Winter_Of_Security_2016).

During the call, we met each other face to face for the first time so can develop a cadence for meeting face to face on the things we want to get done in the next 4 months (the duration of the project).  During the call, I had to express how odd it was that today was just the first official project meeting, but over the past couple months contributors (including members of the MWoS team) have already made some huge leaps and bounds with the project, which is currently still in prototype status.  It's been an amazing effort so far, I'm excited for else we have in store now that we're meeting regularly.

What's been accomplished so far?

- We've released [9 versions](https://github.com/mozilla/ssh_scan/releases) of ssh_scan (0.0.8 - 0.0.15)
- We've created a blog and as of today are now blogging on it.
- We've produced a stable [ssh_scan](https://github.com/mozilla/ssh_scan) binary that allows you to scan ssh services for compliance
- We've built an early prototype of [ssh_scan_api](https://github.com/mozilla/ssh_scan/wiki/ssh_scan-Web-API), which we hope to iterate more on in the coming months
- We've added dozens of OS and SSH Library fingerprints
- We've added auth_method detection, so you can tell whether an endpoint supports publickey auth, password auth, etc.
- We've added multi-threading, multi-ip scanning, and a host key fingerprinting DB
- We've added extensive options for command-line control
- We've natively implemented parts of the ssh protocol and leveraged ruby's net-ssh Library
- We have an extensive unit-test and integration environment built on travis-ci
- We have added unit-test capabilities, so you can [run ssh_scan easily in Jenkins](https://github.com/mozilla/ssh_scan/issues/38)
- We have multiple deployment methods (docker, from source, portable binaries with traveling ruby, and of course gem installs)
- We have begun some [architecture discussions](https://github.com/mozilla/ssh_scan/issues/228) around whether ssh_scan could developed into a service and be plugged into the [Mozilla Observatory](https://observatory.mozilla.org/)
- Fixed dozens of bugs and corner cases as well as many other things

What's next for [ssh_scan](https://github.com/mozilla/ssh_scan)? Well, it's not entirely clear yet, but we have some homework to do for next week to start developing an open road map on our GitHub wiki that we can clearly and openly share with everyone.  We of course plan to iterate on it, but this will be the preliminary map we will be using to help drive the focus of the MWoS project team as well as other contributions that we'll seek to knock out in the coming months.

Lastly, and we've heard this a lot, when will we be releasing 0.1.0?  I can tell you that for some time this has been a little unclear and this is something that the MWoS project team is interested in moving across the finish line, but we'll have some more clarity in the coming weeks.  If I had to put a ballpark figure on it, you can probably expect something before the end of Q1 2017.

Also, here's a photo of our team meeting up on Google Hangout today, we hope to share more about the experiences of the MWoS team soon (likely from their own words) as well as any other interesting [ssh_scan](https://github.com/mozilla/ssh_scan) developments we have in the works here on the blog.

![alt text](https://github.com/mozilla/ssh_scan/raw/gh-pages/_images/mwos_first_meeting.png "First team meeting")

If you have questions or have used ssh_scan and would like to guest blog here about [ssh_scan](https://github.com/mozilla/ssh_scan), please let us know via a [GitHub issue](https://github.com/mozilla/ssh_scan/issues/new).
