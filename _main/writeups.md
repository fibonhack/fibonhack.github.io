---
layout: page
title: "writeups"
---

{% assign ctfs = site.writeups | sort: 'date' | group_by: 'ctf_name' | reverse %}

{% for ctf in ctfs %}

  <h1> {{ ctf.name }} </h1>
  <ul class="post-list">
  {% assign ctf_writeups = ctf.items %}
  {% for writeup in ctf_writeups %}
   <li>
   <a href="{{ writeup.url }}">{{ writeup.title }}{% if writeup.category %} - {{ writeup.category }}{% endif %}</a>
   </li>

  {% endfor %}
  </ul>
{% endfor %}

{% assign ctfs = nil %}
