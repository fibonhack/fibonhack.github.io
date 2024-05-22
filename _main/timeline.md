---
layout: page
title: timeline

timeline:
  - date: January 2020
    title: Sample Text
    description: >
      A paragraph is defined as “a group of sentences or a single sentence that forms a unit” 
      (Lunsford and Connors 116). Length and appearance do not determine whether a section 
      in a paper is a paragraph. For instance, in some styles of writing, particularly journalistic styles, a paragraph can be just one sentence long.
  - date: January 2020
    title: Sample Text
    description: |
      A paragraph is defined as “a group of sentences or a single sentence that forms a unit” (Lunsford and Connors 116).
      Length and appearance do not determine whether a section in a paper is a paragraph.
      For instance, in some styles of writing, particularly journalistic styles, a paragraph can be just one sentence long.
    image: /logo/square/800.png
  - date: January 2020
    title: Sample Title
    description: A paragraph is defined as “a group of sentences or a single sentence that forms a unit” (Lunsford and Connors 116). Length and appearance do not determine whether a section in a paper is a paragraph. For instance, in some styles of writing, particularly journalistic styles, a paragraph can be just one sentence long.
    image: /logo/square/800.png
---

<!-- from https://cruip.com/3-examples-of-brilliant-vertical-timelines-with-tailwind-css/ -->

<!-- vertical line -->
<div class="space-y-8 relative before:absolute before:inset-0 before:ml-1.5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-slate-300 before:to-transparent">

  {% for event in page.timeline %}
  <div class="relative grid md:grid-cols-[1fr_0px_1fr] grid-cols-[0.75rem_1fr] gap-2 justify-items-center place-items-center group">
		<!-- image (optional) -->
    <div class="w-1/2 order-3 col-span-2 md:col-span-1 md:order-1 md:group-even:order-3">
      {% if event.image %}
      <img src="{{ event.image }}" alt="{{ event.title }}" class="border-t-[0.8rem] border-x-[0.6rem] border-b-[2.5rem] border-white">
      {% endif %}
    </div>
    <!-- dot icon -->
    <div class="w-3 h-3 rounded-full border border-white bg-[#27374C] shadow order-1 md:order-2 md:group-even:order-2 ">
    </div>
    <!-- card -->
    <div class="bg-[#181A1B] w-[calc(100%-2rem)] p-4 rounded border border-[#27374C] shadow order-2 md:order-3 md:group-even:order-1">
      <div class="flex items-center justify-between space-x-2 mb-1">
        <div class="font-bold text-zinc-300">{{ event.title }}</div>
        <time class="font-caveat font-medium text-blue-400">{{ event.date }}</time>
      </div>
      <div class="text-[#9D9487] leading-tight not-prose">{{ event.description|markdownify|rstrip|newline_to_br }}</div>
    </div>
  </div>
  {% endfor %}

</div>