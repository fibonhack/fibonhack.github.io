---
layout: page
title: timeline

# Descriptions support Markdown: `|` preserves line breaks; `>` folds line breaks into spaces.
timeline:
  - date: Jun 2019
    title: Team formation
    description: >
      For the first time, the University of Pisa participated in **CyberChallenge.IT**.
      The team was born after the university earned [third place](https://cyberchallenge.it/attack-defense/2019){:target="_blank"}
      in the national competition.
  - date: Jun 2020
    title: CyberChallenge.IT winners
    description: |
      We won [CyberChallenge.IT](https://cyberchallenge.it/attack-defense/2020){:target="_blank"}!
      The team grew.
  - date: Dec 2021
    title: Our first on-site CTF finals
    description: >
      We qualified for the [m0lecon 2021 CTF finals](https://ctftime.org/event/1456/){:target="_blank"}, the CTF and conference organized by the team from [PoliTo](https://pwnthem0le.polito.it){:target="_blank"}.
      We placed 4th overall and first among the Italian teams.
  - date: May 2022
    title: Meta BountyCon
    description: >
      We qualified and were invited to the [Meta BountyCon](https://bountycon.io/){:target="_blank"} bug bounty event in Madrid, Spain.
    image: /assets/images/timeline/spain.jpeg
  - date: Aug 2022
    title: MidnightSun CTF finalists
    description: >
      Together with the **pwnthem0le** team from [PoliTo](https://pwnthem0le.polito.it){:target="_blank"}, we qualified for the [MidnightSun CTF 2022 finals](https://ctftime.org/event/1475/){:target="_blank"} as **AngryGabibbo**.
  - date: Dec 2022
    title: m0lecon 2022 winners
    description: >
      We won the [m0lecon 2022 CTF finals](https://ctftime.org/event/1626){:target="_blank"}.
    image: /assets/images/timeline/m0lecon-2022.jpeg
  - date: May 2023
    title: HackTM CTF finalists
    description: >
      We qualified for the [HackTM CTF finals](https://ctftime.org/event/1971){:target="_blank"}.
    image: /assets/images/timeline/hacktm.png
  - date: Aug 2023
    title: DEF CON CTF finalists and Hack-a-Sat winners
    description: >
      Together with the **mhackeroni** team, we qualified for the [DEFCON](https://www.defcon.org/){:target="_blank"}
      CTF finals and [Hack-a-Sat 4 finals](https://www.hackasat.com/){:target="_blank"}.
      We won [Hack-a-Sat 4](https://ctftime.org/event/2083){:target="_blank"}.
    image: /assets/images/timeline/hack-a-sat.jpeg
  - date: Oct 2023
    title: Internet Festival CTF 2023
    description: >
      We hosted the [Internet Festival 2023 CTF](https://ctftime.org/event/2039){:target="_blank"}, the first on-site CTF in Pisa, with teams from around the world.
    image: /assets/images/timeline/internet-festival-ctf-2023.jpeg
  - date: Oct 2023
    title: High school CTF workshop at Internet Festival 2023
    description: >
      In collaboration with the Cybersecurity National Lab, we hosted the [high school CTF workshop](https://cybersecnatlab.it/gara-cybersicurezza-150-giovani-scuole-superiori-internet-festival-2023/){:target="_blank"} during Internet Festival 2023.
      The workshop introduced high school students to cybersecurity through a CTF.
    image: /assets/images/timeline/Highschools_CTF_Workshop_IF2023.webp
  - date: Dec 2023
    title: m0lecon 2023 finalists
    description: >
      We qualified for the [m0lecon 2023 CTF finals](https://ctftime.org/event/2033){:target="_blank"}.
    image: /assets/images/timeline/m0lecon-2023.jpeg
  - date: May 2024
    title: LakeCTF finalists
    description: >
      We qualified for the [LakeCTF finals](https://ctftime.org/event/2246){:target="_blank"}.
    image: /assets/images/timeline/lake-ctf-2024.jpeg
  - date: May 2024
    title: Space System Security Challenge finalists
    description: >
      We placed 2nd at the [Space System Security Challenge CTF finals](https://www.sssc.space/){:target="_blank"}, hosted by ESA.
    image: /assets/images/timeline/esa.jpeg
  - date: Sep 2024
    title: MOCA CTF 2024
    description: >
      Together with Metro Olografix, we hosted the Metro Olografix Camp 2024 CTF, bringing teams from around the world to Teramo.
    image: /assets/images/timeline/moca-2024.jpeg
  - date: Nov 2024
    title: DefCamp 2024 finalists
    description: >
      We qualified for the [DefCamp CTF 2024 finals](https://ctftime.org/event/2480){:target="_blank"}.
    image: /assets/images/timeline/defcamp-2024.png
  - date: Nov 2025
    title: DefCamp 2025 finalists
    description: >
      We qualified for the [DefCamp CTF 2025 finals](https://ctftime.org/event/2866){:target="_blank"}.
    image: /assets/images/timeline/defcamp-2025.png
  - date: Sep 2026
    title: RomHack Camp CTF 2026
    description: >
      Together with Cyber Saiyan, we hosted the RomHack Camp 2026 CTF, bringing teams from around the world to Rome.
    image: /assets/images/timeline/romhack-camp-ctf-2026.jpeg
  - date: Sep 2026
    title: Sgabeo night at RomHack Camp 2026
    description: >
      At RomHack Camp, we also hosted a sgabeo night so everyone at the camp could enjoy some sgabeo in the fibonhack community area.
    image: /assets/images/timeline/romhack-camp-ctf-2026-sgabeo.jpeg

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