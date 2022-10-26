const copy_svg = `
	<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
`

const copied_svg = `
	<svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-green-500" viewBox="0 0 16 16">
		<path d="M12.736 3.97a.733.733 0 0 1 1.047 0c.286.289.29.756.01 1.05L7.88 12.01a.733.733 0 0 1-1.065.02L3.217 8.384a.757.757 0 0 1 0-1.06.733.733 0 0 1 1.047 0l3.052 3.093 5.4-6.425a.247.247 0 0 1 .02-.022Z"/>
	</svg>
`

const code_snippets = () => {

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

		copy_btn.innerHTML = copy_svg;

		s.appendChild(copy_btn);

		let disabled = false;

		copy_btn.onclick = () => {
			
			if (disabled) return;

			navigator.clipboard.writeText(s.innerText);
			
			copy_btn.innerHTML = copied_svg;

			disabled = true;

			setTimeout(() => {
				copy_btn.innerHTML = copy_svg;
				disabled = false;
			}, 1200);
		}
		
	});
}

const terminal = () => {

	let terminal = document.getElementById("command_form");

	if(!terminal) return;

	terminal.onsubmit = e => {
		
		e.preventDefault();
		
		const command = document.getElementById("command");

		if (!command) return;

		if (command.value === "cat flag.txt") {
			alert("{{kek}}"); 
			return;
		} 

		if (command.value === "cd /") {
			location.href ="/";
			return; 
		}
		if (command.value === "cd .."){
			const location_divided = location.href.split("/"); 
			
			if (location_divided.length < 2) return; 
			
			location.href = location_divided.slice(0, location_divided.length - 2).join('/'); 
			return; 
		}

		if (command.value.startsWith("cd /")){
			location.href = "/" + command.value.split(" /")[1]; 
			return; 
		}

		if (command.value.startsWith("cd ")){
			location.href += command.value.split(" ")[1]; 
			return; 
		}
	}

}

// remove animation-retard elemet view from the dom, 
// in the css only version the retard is provided by changing the visibility property

const hide_retards = () => {
	const retards = document.getElementsByClassName("animation-retard");
	
	const retard = getComputedStyle(document.documentElement)?.getPropertyValue('--retard')?.replace("ms", "") || 900; 

	[].forEach.call(retards, r => {
		r.classList.add("hidden");
	});

	setTimeout(() => {
		[].forEach.call(retards, r => {
			r.classList.remove("hidden");
		});
	}, retard);
	
}

window.onload = () => {

	// remove no-js class, thus css will know that css is active
	[].forEach.call(
		document.getElementsByClassName("no-js"), 
		no_js => {
			no_js.classList.remove("no-js");
		}
	);

	terminal();
	code_snippets();
	hide_retards();
}
