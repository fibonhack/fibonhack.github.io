---
layout: page
title: "home"
---

# About us
fibonhack is a CTF team born after [CyberChallenge](https://cyberchallenge.it/) 2019 by a group of students from [UniPi](https://www.unipi.it/).
We are interested in computer security, but no we can't hack your friend's Facebook account

Check out how good (bad) we are doing at [CTFTime](https://ctftime.org/team/117538)

{% if site.social.email %} Contact us at `{{site.social.email}}` {% endif %}

# News
We just organized our first [CTF event](/events/2023/ifctfquals), check it out!


# Members

{% for author in site.authors %}

{% assign author_url = "/members/" | append: author.short_name %}
* <abbr title="{{ author.position }}">{{ author.skill }}</abbr> [{{ author.short_name }}]( {{ author_url  }} )
{% assign author_url = nil %}

{% endfor %}
