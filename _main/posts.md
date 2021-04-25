---
layout: page
title: "posts"
---

{% assign allposts = site.ourposts | sort: 'date' | reverse %}

{% for post in allposts %}
  <ul class="post-list">
    <li>
    <a href="{{ post.url }}">{{ post.title }} - {{ post.date | date: "%-d %b %Y" }}</a>
    </li>
  </ul>
{% endfor %}
{% assign allposts = nil %}
