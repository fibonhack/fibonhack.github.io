---
layout: page
title: "logo"
---
{% assign logo_collection = site.collections | find: "label", "logo" %}

{% assign logo_groups = logo_collection.files | group_by_exp: "item", "item.path | split: '/' | slice: 1 | array_to_sentence_string, ''" %}
{% for group in logo_groups %}
  <h1>{{ group.name }}</h1>
  <ul class="post-list">
    <li>
	{% assign files = group.items | sort: "basename" %}
	{% for file in files %}
	<a href="{{ file.path | replace: '_', '/' }}" target="_blank">{{ file.basename }}px</a>{% unless forloop.last %}, {% endunless %}
	{% endfor %}
    </li>
  </ul>
{% endfor %}