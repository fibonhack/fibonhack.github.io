---
ctf_name: "m0lecon 2020 Teaser"
title:	"CSS shitty scaling"
date:	2020-05-24
category: "misc"
author: "lorenz"
---

We are given a flag.html file that is 231M in size. Looking at what's inside it's clear what it does: it's using divs as individual pixels to dysplay an image trough some css animations, but it's to mutch stuff to render and the browser freezes.

flag.html
```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
</head>
<body>
<div style="width=1920px; height=1080px">
<div style="display: table-row;">

<style>
@keyframes slide0 {
	from {transform: translate(1860px, 166px);}
	to {transform: translate(1886px, 766px);}
}
</style>
<div style="height: 1px; width: 1px; display: table-cell;
	animation: slide0 5s 0s infinite alternate cubic-bezier(0,1,1,0);
	background-color: #000000ff;">
</div>
.
.
.
<style>
@keyframes slide800399 {
	from {transform: translate(808px, 359px);}
	to {transform: translate(-968px, -63px);}
}
</style>
<div style="height: 1px; width: 1px; display: table-cell;
	animation: slide800399 5s 0s infinite alternate cubic-bezier(0,1,1,0);
	background-color: #00000000;">
</div>
</div>

</div>
</body>
</html>
```

Testing with just a few divs you can see that each div is animated to oscillate between 2 points stopping for a bit in the middle, so the point where the div stops for longer must be the correct position in order to display the flag. With a bit more testing you can see that the point where the div stops is the point in the middle of the keyframe animation, so for example given the animation `slide0`, we are only interested in displayng the div in this position: `transform: translate((808px - 968px) / 2, (359px - 63px) / 2)`.

One smart way to display the final image would be to calculate the final position for each div (pixel) and ricreate the image with let's say python's PIL, but i wasn't sure if translate would move the div relative to (0,0) or relative to it's current position. I went the lazy way and just changed the html so that instead of the animation, the div is drawn in the middle point.

One final catch, since the flag was written in white part of it was not readable, but changing the body background color to blue did the trick.

![Screenshot]({{ site.baseurl }}/images/posts/2020/shitty-scaling-flag.png)