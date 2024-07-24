---
layout: page
title: timeline

# in the description you can use markdown, `|` ignores the newline, `>` keeps the newlines in the output
timeline:
  - date: Jun 2019
    title: Team Formation
    description: >
      The University of Pisa partecipates for the first time at **CyberChallenge.IT**,
      after the [third place](https://cyberchallenge.it/attack-defense/2019){:target="_blank"} 
      in the national competition the team was born.
  - date: Jun 2020
    title: CyberChallenge.IT winners
    description: |
      We won the [CyberChallenge.IT](https://cyberchallenge.it/attack-defense/2020){:target="_blank"}!
      The team grows :super:.
  - date: Dec 2021
    title: Our first CTF final on site
    description: >
      We qualified for the m0lecon 2021 ctf final, the ctf and conference organized by the team from [PoliTo](pwnthem0le.polito.it){:target="_blank"}.
      We placed 4th and first among the Italian teams.
  - date: May 2022
    title: Meta BountyCon
    description: >
      We qualified and got invited to the [Meta BountyCon](https://bountycon.io/){:target="_blank"} bug bounty event in Madrid, Spain.
    image: /assets/images/timeline/spain.jpg
  - date: Dec 2022
    title: m0lecon 2022 winners
    description: >
      We won the [m0lecon 2022](https://pwnthem0le.polito.it/){:target="_blank"} 
      ctf final, the first time for the University of Pisa.
    image: https://pbs.twimg.com/media/Fh8WA3sWQAA_HN-?format=jpg&name=large
  - date: May 2023
    title: HackTM CTF Finals
    description: >
      We qualified for the [HackTM](https://hacktm.ro/){:target="_blank"} 
      ctf final, the first time for the University of Pisa.
  - date: Aug 2023
    title: DEFCON CTF Finals & HackASat winners
    description: >
      We qualified for the [DEFCON](https://www.defcon.org/){:target="_blank"} 
      ctf final and won the [HackASat](https://www.hackasat.com/){:target="_blank"} 
      ctf, the first time for the University of Pisa.
    image: https://pbs.twimg.com/media/F3_mGD5W0AA49NQ?format=jpg&name=4096x4096
  - date: Aug 2023
    title: MidnightSun CTF finalists
    description: >
      We qualified for the [MidnightSun](https://midnightsunctf.se/){:target="_blank"} 
      ctf final, the first time for the University of Pisa.
  - date: Sep 2023
    title: OliCyber organizers
    description: >
      We organized the [OliCyber](https://olicyber.it/){:target="_blank"} 
      ctf, the first time for the University of Pisa.
  - date: Oct 2023
    title: Internet Festival CTF & High school organizers
    description: >
      We qualified for the [Hack.lu](https://hack.lu/){:target="_blank"} 
      ctf final, the first time for the University of Pisa.
  - date: May 2024
    title: LakeCTF finalists
    description: >
      We qualified for the [LakeCTF](https://lakectf.it/){:target="_blank"} 
      ctf final, the first time for the University of Pisa.
  - date: May 2024
    title: Space System Security Challenge finalists
    description: >
      We qualified for the [Space System Security Challenge](https://www.sssc.space/){:target="_blank"} 
      ctf final, the first time for the University of Pisa.
---

<!-- from https://cruip.com/3-examples-of-brilliant-vertical-timelines-with-tailwind-css/ -->
<!-- TODO: fix hardcoded values (colors etc) -->

<!-- vertical line -->
<div class="space-y-8 relative before:absolute before:inset-0 before:ml-1.5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-slate-300 before:to-transparent">

  {% for event in page.timeline %}
  <div class="relative grid md:grid-cols-[1fr_0px_1fr] grid-cols-[0.75rem_1fr] gap-2 justify-items-center place-items-center group">
    <!-- image (optional) -->
    <div class="md:w-1/2 w-4/5 order-3 col-span-2 md:col-span-1 md:order-1 md:group-even:order-3">
      {% if event.image %}
      <img src="{{ event.image }}" alt="{{ event.title }}" class="w-full aspect-[35/42] object-cover border-t-[0.8rem] border-x-[0.6rem] border-b-[2.5rem] border-white">
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
      <div class="text-[#9D9487] leading-tight not-prose [&_a]:underline">{{ event.description|markdownify|rstrip|newline_to_br }}</div>
    </div>
  </div>
  {% endfor %}

</div>