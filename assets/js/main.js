const copy_svg = `
	<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
`

const copied_svg = `
	<svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-green-500" viewBox="0 0 16 16">
		<path d="M12.736 3.97a.733.733 0 0 1 1.047 0c.286.289.29.756.01 1.05L7.88 12.01a.733.733 0 0 1-1.065.02L3.217 8.384a.757.757 0 0 1 0-1.06.733.733 0 0 1 1.047 0l3.052 3.093 5.4-6.425a.247.247 0 0 1 .02-.022Z"/>
	</svg>
`

const add_code_snippets_copy_btn = () => {

	const snippets = document.querySelectorAll(".highlighter-rouge > .highlight");

	[].forEach.call(snippets, snippet => {
		
		snippet.classList.add("relative", "group");
		
		const copy_btn = document.createElement("div");

		copy_btn.classList.add(
			"absolute", "hidden", "p-2", "right-1",
			"top-1", "color-zinc-400", "group-hover:block", "bg-[#2d333b]",
			"rounded-lg", "cursor-pointer", "hover:brightness-150"
		);
		
		copy_btn.innerHTML = copy_svg;
		snippet.appendChild(copy_btn);

		let copy_disabled = false;

		copy_btn.onclick = () => {
			
			if (copy_disabled) return;

			navigator.clipboard.writeText(snippet.innerText);
			
			copy_btn.innerHTML = copied_svg;

			copy_disabled = true;

			setTimeout(() => {
				copy_btn.innerHTML = copy_svg;
				copy_disabled = false;
			}, 1200);
		}
		
	});
}


// for when @barsa and @nick0ve go nuts and break balls
// HOW TO ADD A COMMAND
// - add an if
// - return the output as an html string

const handle_command = command => {

	if (command === "help")
		return `<div class="text-white container mb-6">
			ls  &nbsp;&nbsp;page listing<br>
			cd  &nbsp;&nbsp;change page<br>
			cat &nbsp;show a file<br>
		</div>`;

	if (command === "ls")
		return `<div class="text-white container mb-6">
			Home<br>
			Resources<br>
			Posts<br>
			WriteUps
		</div>`;
	
	// for @just-hms don't delete me 
	if (command === "cat tangerine.txt") 
		return `<h1 class="container text-2xl mb-6">🍊</h1>`;


	if (command === "cat flag.txt") 
		return `<div class="text-white container mb-6">
			{{kek}}
		</div>`;

	if (command === "cat page.txt") {

		const mains = document.getElementsByClassName("main");
		if (mains.length == 0) return;
		
		const last_main = mains[0];
		return last_main.outerHTML;
	} 

	if (command === "cd /") {
		location.href ="/";
		return; 
	}

	if (command === "cd .."){
		const location_divided = location.href.split("/"); 
		location.href = location_divided.slice(0, location_divided.length - 2).join('/'); 
		return; 
	}

	if (command.startsWith("cd /")){
		location.href = "/" + command.split(" /")[1]; 
		return; 
	}

	if (command.startsWith("cd ")){
		location.href += command.split(" ")[1]; 
		return; 
	}

	if(command == ""){
		return;
	}

	return `<div class="text-red-500 container mb-6">
		${command}: command not found
	</div>`; 
	
}

const terminal = () => {

	// find the last terminal form in the dom
	const terminals_form = document.getElementsByClassName("terminal_form");
	if(terminals_form.length == 0) return;
	const terminal_form = terminals_form[terminals_form.length - 1];

	terminal_form.onsubmit = e => {
		
		e.preventDefault();

		// find the last terminal in the dom (the all object)
		const terminals = document.getElementsByClassName("terminal");
		if(terminals.length == 0) return;
		const terminal = terminals[terminals.length - 1];
		
		// find the last input
		const inputs = terminal_form.getElementsByTagName("input");
		if (inputs.length == 0) return;
		const last_input = inputs[inputs.length - 1];

		// get the ouptut from the handle_command function
		let output = handle_command(last_input.value);

		// return if there is no output
		if(output == undefined || output == null) output = "";

		const clone = terminal.cloneNode(true);
		const old_terminal = terminal.parentElement.insertBefore(clone, terminal);
		const old_input = old_terminal.getElementsByTagName("input")[0];

		old_input.disabled = true;
		
		const output_element = document.createElement("div");
		terminal.parentElement.insertBefore(output_element, terminal);
		
		output_element.outerHTML = output;

		last_input.value = "";
		window.scrollTo(0, document.body.scrollHeight);
	}
}

// remove animation-retard element view from the dom, 
// in the css only version the retard is provided by changing the visibility property

const hide_retards = () => {
	const retards = document.getElementsByClassName("animation-retard");
	
	const retard = getComputedStyle(document.documentElement)?.getPropertyValue('--retard')?.replace("ms", "") || 900; 

	[].forEach.call(retards, r => r.classList.add("hidden"));

	setTimeout(() => {
		[].forEach.call(retards, r => {
			r.classList.remove("hidden");
		});
	}, retard);
	
}

// low quality image preload from https://medium.com/@imgix/lqip-your-images-for-fast-loading-2523d9ee4a62
const lqip = () => {
	[...document.getElementsByClassName('lqip')].forEach(e => e.setAttribute('src', e.getAttribute('data-src')));
}

window.onload = () => {

	// remove no-js class making css kow that javascript is active

	[].forEach.call(
		// over
		document.getElementsByClassName("no-js"), 
		// do
		no_js => {
			no_js.classList.remove("no-js");
		}
	);

	terminal();
	add_code_snippets_copy_btn();
	hide_retards();
	lqip();
}
