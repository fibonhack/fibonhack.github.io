---
layout: page
title: timeline
---

<!-- from https://cruip.com/3-examples-of-brilliant-vertical-timelines-with-tailwind-css/ -->

<!-- vertical line -->
<div class="space-y-8 relative before:absolute before:inset-0 before:ml-1.5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-slate-300 before:to-transparent">

	{% for event in site.data.timeline %}
	<div class="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
		<!-- dot icon -->
		<div class="w-3 h-3 rounded-full border border-white bg-[#27374C] text-slate-500 shadow shrink-0 md:order-1 md:group-odd:-translate-x-[calc(2rem-50%)] md:group-even:translate-x-[calc(2rem-50%)]">
		</div>
		<!-- card -->
		<div class="w-[calc(100%-3rem)] md:w-[calc(50%-2rem)] bg-[#181A1B] p-4 rounded border border-[#27374C] shadow">
			<div class="flex items-center justify-between space-x-2 mb-1">
				<div class="font-bold text-zinc-300">{{ event.title }}</div>
				<time class="font-caveat font-medium text-blue-400">{{ event.date }}</time>
			</div>
			<div class="text-[#9D9487] leading-tight not-prose">{{ event.description|markdownify|rstrip|newline_to_br }}</div>
		</div>
	</div>
	{% endfor %}

</div>