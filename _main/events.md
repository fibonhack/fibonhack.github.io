---
layout: page
title: "events"
---


{% assign allevents = site.ourevents | sort: 'date' | reverse %}
{% for event in allevents %}
<ul class="event-list">
    <li>
        <a href="{{ event.url }}">{{ event.title }} - {{ event.date | date: "%-d %b %Y" }}</a>
    </li>
</ul>
{% endfor %}

{% assign allevents = nil %}
