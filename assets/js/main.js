window.onload = () =>{

	const retards = document.getElementsByClassName("retarded");
	setTimeout(() => {
		[].forEach.call(retards, r => {
			r.classList.remove("hidden");
		});
	}, 900);

	const snippets = document.querySelectorAll(".highlighter-rouge > .highlight");

	[].forEach.call(snippets, s => {
		
		s.classList.add("relative", "group");
		
		const copy_btn = document.createElement("div");
		copy_btn.classList.add(
			"absolute",
			"hidden",
			"p-2",
			"right-1",
			"top-1",
			"color-zinc-400",
			"group-hover:block",
			"bg-[#2d333b]",
			"rounded-lg",
			"cursor-pointer",
			"hover:brightness-150"
		);

		copy_btn.innerHTML = `
			<svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6" fill="currentColor" viewBox="0 0 16 16">
				<path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1v-1z"/>
				<path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5h3zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3z"/>
			</svg>
		`;

		s.appendChild(copy_btn);

		let disabled = false;

		copy_btn.onclick = () => {
			
			if (disabled) return;

			navigator.clipboard.writeText(s.innerText);
			
			copy_btn.innerHTML = `
				<svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-green-500" viewBox="0 0 16 16">
					<path d="M12.736 3.97a.733.733 0 0 1 1.047 0c.286.289.29.756.01 1.05L7.88 12.01a.733.733 0 0 1-1.065.02L3.217 8.384a.757.757 0 0 1 0-1.06.733.733 0 0 1 1.047 0l3.052 3.093 5.4-6.425a.247.247 0 0 1 .02-.022Z"/>
				</svg>
			`;

			disabled = true;

			setTimeout(() => {
				copy_btn.innerHTML = `
					<svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6" fill="currentColor" viewBox="0 0 16 16">
						<path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1v-1z"/>
						<path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5h3zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3z"/>
					</svg>
				`;
				disabled = false;
			}, 1200);
		}
		
	});
}