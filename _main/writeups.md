---
layout: page
title: "writeups"
---

{% assign ctfs = site.writeups | sort: 'date' | group_by: 'ctf_name' | reverse %}

{% for ctf in ctfs %}
  <h1> {{ ctf.name }} </h1>
  <ul class="post-list">
  {% assign ctf_writeups = ctf.items | sort: 'title' | group_by: 'category' %}
  {% for writeup_group in ctf_writeups %}
    {% for post in writeup_group.items %}
         <li>
   <a href="{{ post.url }}">{{ post.title }}{% if post.category %} - {{ post.category }}{% endif %}</a>
   </li>
    {% endfor %}
  {% endfor %}
  </ul>
{% endfor %}

{% assign ctfs = nil %}
