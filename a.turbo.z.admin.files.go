/*
Turbo - A cross-platform, high-performance HTTP web server with a real-time, visual management interface. Manage unlimited domains and multi-level wildcard subdomains, SSL certificates, URI rewrites, request preprocessing, fine-grained request rate and size limiting, as well as custom aliases, headers, MIMEs, and indexes.
Copyright (C) 2026 OKZGN

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please visit one of the following:
- https://okzgn.com/#contact
- https://okzgn.github.io/#contact
*/

package main

var (
	_AF = map[string]map[string]string{
		"admin": {
			"m.css": `@font-face {
	font-family: 'A';
	src: url(/admin:r.ttf);
	font-weight: normal;
}
@font-face {
	font-family: 'A';
	src: url(/admin:b.ttf);
	font-weight: bold;
}
*, *::after, *::before {
	outline: 0;
	border: 0;
	margin: 0;
	padding: 0;
	box-sizing: border-box;
	font-family: 'A', helvetica;
	word-spacing: 0.25rem;
	line-height: 1.25;
	transition: all 0.125s;
}
* {
	font-size: 1rem;
	scrollbar-color: #808080 #f0f0f0;
	scrollbar-width: thin;
}
:active, :focus {
	outline: 0;
	-webkit-tap-highlight-color: transparent;
}
::selection {
	opacity: 1;
	background: #000 !important;
	color: #fff;
}
::-webkit-scrollbar {
	width: 0.25rem;
	height: 0.25rem;
}
::-webkit-scrollbar-thumb { background: rgba(0, 0, 0, 0.5); }
::-webkit-scrollbar-track { background: #f0f0f0; }
html, body {
	width: 100%;
	height: 100%;
}
a {
	text-decoration: none;
	color: #004e9b;
}
a:hover, a:active, a:focus { color: #000; }
body {
	overscroll-behavior: none;
	background-color: #f0f0f0;
	text-align: left;
	color: #000;
}`,

			"#.html": `<!DOCTYPE html>
<html spellcheck="false" data-signin>

<head>
<title>Turbo | Administración</title>
<link rel="icon" href="/admin:i.png">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, user-scalable=no">
<meta name="description" content="Acceso a la interfaz de administración del servidor web.">
<meta name="author" content="Elías A. Soshina">
<meta name="theme-color" content="#004e9b">
<link rel="stylesheet" href="/admin:m.css">
<style>
body { display: flex; justify-content: center; }
h1 { margin-top: 2rem; }
h1 img { margin-right: 1rem; height: 3.125rem; }
h1, h1 a { line-height: 0; color: #000; }
h1 img, h1 span { display: inline-block; vertical-align: middle; }
h1 span { font-size: 1.875rem; }
h1, h2 { margin-bottom: 1rem; }
h2 { font-size: 1.25rem; color: rgba(0, 0, 0, 0.5); }
form { text-align: center; align-self: center; }
fieldset { background: linear-gradient(to bottom, #fff , transparent 1rem); box-shadow: 0 0 3rem rgba(0, 0, 0, 0.125); width: 15rem; }
[data-l] { position: relative; left: 0; animation: a 0.5s linear 0s alternate infinite forwards; box-shadow: 0 0 0.5rem rgba(0, 0, 0, 0.125); }
@keyframes a { to { left: 0.25rem; background: #331b68; color: rgba(255, 255, 255, 0.75); } }
input { border: 0; line-height: 1; background: transparent; display: inline-block; }
input[type="text"], input[type="password"] { padding: 1rem; border-top: 1px solid rgba(0, 0, 0, 0.25); background: rgba(255, 255, 255, 0.5); width: 100%; }
input[type="text"]:hover, input[type="password"]:hover, input[type="text"]:focus, input[type="password"]:focus { border-color: #000; background: #fff; }
input[type="submit"]{ padding-top: 1rem; padding-bottom: 1rem; background: #004e9b; color: #fff; font-weight: bold; cursor: pointer; margin: 0 0 0.5rem auto; width: calc(100% - 6rem); font-size: 1.125rem; }
input[type="submit"]:hover, input[type="submit"]:active, input[type="submit"]:focus { background: #001b68; color: rgba(255, 255, 255, 0.875); }
[data-ok], [data-err] { padding: 1rem; background: #c00; color: #fff; }
[data-ok] { background: #090; }
[data-hidden] { display: none; }
</style>
<script>
function $(a, b, c, d, e, f, g, h, i, j, k){
	f = typeof b == 'function',
	h = function(g){
		d = (!f ? d : c), d = (typeof d != 'function' ? function(a, b){ console.error(b + ': ' + a); } : d),
		d.call(this, g, this.status);
	}
	e = new XMLHttpRequest(),
	e.onerror = function(){ h.call(this, 'Intente nuevamente'); },
	e.onabort = function(){ h.call(this, 'Petición cancelada'); },
	e.onload = function(){
		g = this.responseText;
		switch(this.status){
			case 200: case 201: case 304:
				if(g = _(g)){ return h.call(this, g); }
				(!f ? c : b).call(this, this.responseText, this.status);
			break;
			default: h.call(this, g);
		}
	};
	if(self['URLSearchParams']){
		k = a.indexOf('?'), i = (k != -1 ? a.slice(k + 1) : ''), j = new URLSearchParams(i);
		a = !i ? a : a.substring(0, k) + (j.toString() || i);
	}
	e.open('POST', a), e.send(!f ? b : null);
}
function _(a){ return (a.indexOf('data-signin') != -1 ? 'Sin respuesta' : (!a ? 'Vuelva a intentarlo' : null)); }
function A(a, b){
	delete G.dataset.ok; delete G.dataset.err;
	G.dataset[b || 'err'] = '', G.innerText = a, clearTimeout(E.T), E.T = setTimeout(function(){ G.dataset.hidden = ''; }, 6789);
}
document.addEventListener('DOMContentLoaded', function(G, E, T, U, P){
	document.ondragstart = document.onselectstart = function(a){ return a.preventDefault(); };
	G = document.getElementById('G'), E = document.getElementById('E'),
	T = document.querySelector('[type="submit"]'),
	U = document.querySelector('[name="u"]'), P = document.querySelector('[name="p"]');
	E.onsubmit = function(I, M){
		I.preventDefault(), M = 'ok';
		if(!U.value.length){ return U.focus(); }
		if(!P.value.length){ return P.focus(); }
		T.blur(), T.dataset.l = '', delete G.dataset.hidden,
		$(E.getAttribute('action'), new FormData(E),
		function(Z){
			delete T.dataset.l;
			if(Z.indexOf(M) === 0){
				setTimeout(function(){ self.location = '/admin:inside:?' + Z; }, 567);
				return A('Ingresando. . .', M);
			}
			A(Z);
		},
		function(Z){ delete T.dataset.l, U.value = '', P.value = '', A('Inautorizado'); });
	};
});
</script>
</head>
<body>
<form id="E" action="/admin:" method="post">
<fieldset>
	<h1><a target="_blank" href="https://okzgn.com"><img src="/admin:i.png" alt="Logotipo de OKZGN"><span>Turbo</span></a></h1>
	<h2>Administración</h2>
	<p id="G" data-hidden></p>
	<input type="text" name="u" placeholder="Usuario">
	<input type="password" name="p" placeholder="Contraseña"><input type="submit" value="Entrar >">
</fieldset>
</form>
</body>
</html>`,
		},

		// Here starts inside's content

		"inside": {
			"#.html": `<!DOCTYPE html>
<html spellcheck="false" data-inside>

<head>
<title>Turbo | Administración</title>
<link rel="icon" href="/admin:i.png">

<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, user-scalable=no">
<meta name="description" content="Interfaz de administración del servidor web.">
<meta name="author" content="Elías A. Soshina">
<meta name="theme-color" content="#ffffff">

<link rel="stylesheet" href="/admin:m.css">
<style>
body, #R { overflow-x: hidden; }
#R { overflow-y: hidden; }
.L { overflow-y: auto; }
#R > div { float: left; }
header { max-height: 3.25rem; }
.L { max-height: 50vh; }
#R > div { width: calc(50% - 1rem); }
.L [data-x] + a { width: calc(100% - 2rem); }
aside > section, header, .F, .O, .L { width: 100%; }
[data-error]::after, [data-ok]::after, [data-x], #Z .L a::after { width: 1.5rem; }
[data-error]::after, [data-ok]::after, [data-x], #Z .L a::after { height: 1.5rem; }
h1 img { height: 2rem; }
legend { text-transform: uppercase; }
header p, .F, .O, [data-error]::after, [data-ok]::after, [data-x], #Z .L a::after { text-align: center; }
header a, .F, .F + ul, .O, legend, fieldset a::before, [href$="setC"] { font-weight: bold; }
.D a i { font-style: normal; }
[data-error]::after, [data-ok]::after, [data-x], #Z .L a::after { line-height: 1.5; }
h1, h1 a, header a { line-height: 0; }
h2, aside > section a, section > a:first-child { font-size: 1.2rem; }
#T { font-size: 1.5rem; }
ul { list-style: none; }
aside, section, #T + ul, #R > ul, #Z .L { justify-content: center; }
header h1, header h2, header p, .D a, header a > *, header a::after, aside > fieldset { align-self: center; }
header p { flex-grow: 1; }
header a { flex-shrink: 0; }
aside, .F + ul, section, .D, .L { flex-wrap: wrap; }
header, aside, .F + ul, section, .D, .L, header a { display: flex; }
main, #R, [data-hidden], #O, #I .L a::after { display: none; }
#B [data-hidden] { display: none !important; }
header a:last-child::after, fieldset a::before, .F::before, .O::before, [data-error]::after, [data-ok]::after, .D a *, #Z .L a::after, .F + ul a, #B li::before, [data-x], legend::before { display: inline-block; }
main[data-std-site], section[data-std-subdomain], .F { display: block !important; }
[data-error]::after, .L [data-x] + a:hover, .L [data-x] + a:active, .L [data-x] + a:focus { background: #fff; }
[data-error]::after, [data-x]:hover, [data-x]:active, [data-x]:focus, #Z .L a:hover::after, #Z .L a:active::after, #Z .L a:focus::after { background: #c00; }
[data-ok]::after { background: #090; }
[data-x], .D a span, #Z .L a::after { background: rgba(0, 0, 0, 0.125); }
legend { background: linear-gradient(to top, transparent, #fff 50%); }
header, section, fieldset, .D { background: linear-gradient(to top, transparent calc(100% - 1rem), #fff); }
[data-error], [data-x], #D, #Z .L a::after { color: #c00; }
.O { color: #004e9b !important; }
[data-ok], .D a span::after { color: #090 !important; }
[data-https] { color: #360 !important }
header a, .F { color: #000; }
section > a, .D a span, #Z .L a { color: #333; }
ul a, .L a i { color: #666; }
#B li::before { color: rgba(0, 0, 0, 0.25); }
[data-error]::after, [data-ok]::after, [data-x]:hover, [data-x]:active, [data-x]:focus, #Z .L a:hover::after, #Z .L a:active::after, #Z .L a:focus::after { color: #fff; }
[data-error]::after, [data-ok]::after, [data-x], #Z .L a::after { border-radius: 50%; }
header { border-bottom: 1px solid rgba(0, 0, 0, 0.125); }
section, fieldset, .D { border: 1px solid rgba(0, 0, 0, 0.125); }
.D .L a:not([data-x]){ border-top: 1px solid rgba(0, 0, 0, 0.125); }
[data-error], [data-ok], legend { cursor: pointer; }
body { cursor: default; }
a:hover, a:active, a:focus { transform: scale(1.05); }
#B li::before { transform: scale(1.5); }
.D .L a:hover, .D .L a:active, .D .L a:focus, header a:hover, header a:active, header a:focus, #Z .L a { transform: none; }
header a:hover, header a:active, header a:focus { opacity: 1; }
header a { opacity: 0.5; }
#R > div { margin: 0 0.5rem 1rem 0.5rem; }
section, .L a:first-child, .L a:first-child + a { margin-top: 1rem; }
fieldset li { margin-top: 0.25rem; }
fieldset + section, #Z .L a, fieldset li:first-child { margin-top: 0; }
h1, h2 { margin-right: 1rem; }
.F::before, .O::before, [data-x], fieldset a::before, #B li::before, fieldset, legend::before { margin-right: 0.5rem; }
header a:last-child::after, #Z .L a::after, fieldset { margin-left: 0.5rem; }
.O, .O + a, .F, .F + a, .F + ul li:first-child, fieldset a, #Z .L a:first-child { margin-left: 0 !important; }
header a, aside a, section > a, .F + ul li, [data-error]::after, [data-ok]::after, .D span::after, #Z .L a, section > a [data-x] { margin-left: 1rem; }
.F, .F + ul, .D, section > a, fieldset, #Z .L a { margin-bottom: 1rem; }
legend { padding: 0.5rem 1rem; }
main[data-std-site], aside, fieldset ul, .D, [data-error], [data-ok] { padding: 1rem; }
header { padding: 0 1rem; }
.D a *, #I .L a:not([data-x]) { padding: 0.5rem; }
section { padding: 1rem 0.5rem 0 0.5rem; }
#R > .F, #R > .F + ul, section > a { padding: 0 0.5rem; }
header h1 { padding: 1rem 0; }
#B li::before { content: '·'; }
#T::before { content: '<'; }
#R > .F::before { content: '< Subdominio: '; }
.O::before { content: '+'; }
header a:last-child::after, .D a span::after, fieldset a::before, legend::before { content: '>'; }
[data-error]::after, [data-ok]::after, #Z .L a::after { content: 'X'; }
[data-load] { animation: l 0.5s infinite alternate; }
legend[data-std]::before { transform: rotate(90deg); }
@keyframes l { from { background: transparent; } to { background: #fff; } }
[data-load-link] { animation: m 0.5s infinite alternate; }
@keyframes m { to { color: #090; } }
[data-large-ok], [data-large-error], article {
	position: fixed;
	width: 100%;
	z-index: 1;
	top: 0;
	left: 0;
}
[data-large-ok], [data-large-error] { padding: 1rem 3.125rem; }
[data-large-ok]::after, [data-large-error]::after {
	position: absolute;
	margin: 0;
	top: 0.875rem;
	right: 0.625rem;
}
[data-large-error] {
	color: #fff;
	background: #c00;
}
[data-large-error]::after {
	color: #c00;
	background: #fff;
}
[data-large-ok] {
	color: #fff !important;
	background: #090;
}
[data-large-ok]::after {
	color: #090;
	background: #fff;
}
@keyframes n {
	25% { backdrop-filter: blur(1px); }
	50% { backdrop-filter: blur(2px); }
	75% { backdrop-filter: blur(3px); }
	to {
		backdrop-filter: blur(4px);
		background: rgba(255, 255, 255, 0.25);
	}
}
@keyframes o { to { background: rgba(0, 0, 0, 0.45); } }
@keyframes p { to { background: #f80; } }
article {
	height: 100%;
	animation: n 0.125s 1 forwards;
}
article div, article button:not([data-first]) { animation: o 0.125s 1 forwards; }
article, article div {
	display: flex;
	justify-content: center;
	flex-flow: column;
}
article div {
	align-self: center;
	padding: 0 1rem 1rem 1rem;
	width: 25rem;
	max-width: 25rem;
}
article.B div {
	max-width: 30rem;
	width: 30rem;
}
article div > * { margin-top: 1rem; }
article p, article button { color: #fff; }
article input, article button { padding: 0.5rem 1rem; }
article button { cursor: pointer; }
article button:hover, article button:active, article button:focus {
	background: #000 !important;
	color: rgba(255, 255, 255, 0.875);
}
article [data-first] {
	animation: p 0.15s 1 forwards;
	font-weight: bold;
	margin-left: 1rem;
}
article [data-first]:hover, article [data-first]:active, article [data-first]:focus { background: #c53 !important; }
article span { text-align: right; }
article input { width: 100%; }
article p { 
  word-wrap: break-word;
  overflow-wrap: break-word;
}
::placeholder {
	color: #000;
	opacity: 0.5;
}
@media screen and (max-width: 640px), screen and (max-width: 480px){
	[data-ok], [data-error] {
		padding: 1rem;
		position: fixed;
		width: 100%;
		z-index: 1;
		top: 0;
		left: 0;
	}
	[data-ok]::after, [data-error]::after {
		position: absolute;
		margin: 0;
		top: 0.875rem;
		right: 0.625rem;
	}
	[data-error] {
		color: #fff;
		background: #c00;
	}
	[data-error]::after {
		color: #c00;
		background: #fff;
	}
	[data-ok] {
		color: #fff !important;
		background: #090;
	}
	[data-ok]::after {
		color: #090;
		background: #fff;
	}
	article.B div { max-width: 100%; }
	#Z .L { flex-flow: column; }
	#Z .L a {
		align-self: center;
		margin-left: 0;
	}
	.F + ul li { margin: 0.5rem; }
	.F + ul li:first-child { margin-left: 0.5rem !important; }
	.D { width: calc(100% - 1rem) !important; }
	.F, .F + ul { margin-bottom: 0.5rem; }
	.F + ul + section { margin-top: 0.5rem; }
	aside { padding: 1rem 0.5rem; }
	aside > section {
		margin-left: 0.5rem;
		margin-right: 0.5rem;
	}
	fieldset li {
		padding-right: 1rem;
		margin-top: 0.5rem;
		text-indent: -0.5rem;
		position: relative;
		left: 1rem;
	}
	article div {
		width: 100%;
	}
}
</style>
<script>
document.addEventListener('DOMContentLoaded', function($$, $Z, $Y, $X, $W, A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z, Z_, Y_, X_, W_, V_, U_, T_){
	$Z = { a: '/admin:inside:set', b: 'ok' };
	function _(x, y, z){ return (z || document)[!y ? 'querySelectorAll' : 'querySelector'](x); }
	function $(a, b, c, d, e, f, g, h, i, j, k, l){
		f = typeof b == 'function',
		h = function(g){
			d = (!f ? d : c), d = (typeof d != 'function' ? function(a, b){ console.error(b + ': ' + a); } : d),
			(delete N.parentNode.dataset.load), d.call(this, g, this.status);
		}
		e = new XMLHttpRequest(),
		e.onerror = function(){ h.call(this, 'Intente nuevamente'); },
		e.onabort = function(){ h.call(this, 'Petición cancelada'); },
		e.onload = function(){
			g = this.responseText;
			switch(this.status){
				case 200:
				case 201:
				case 304:
					if(g = _U(g)){ return h.call(this, g); }
					(delete N.parentNode.dataset.load), (!f ? c : b).call(this, this.responseText, this.status);
				break;
				default: h.call(this, g);
			}
		};
		
		if(self['URLSearchParams']){
			(k = a.indexOf('?')),
			(i = (k != -1 ? a.slice(k + 1) : '')),
			(j = new URLSearchParams(i)),
			(a = !i ? a : a.substring(0, k) + '?' + (j.toString() || i));
		}

		e.open('POST', /* With no slash at the end: 'http://localhost' + a.replace('default://home', '')*/a),
		e.setRequestHeader($Z.b, sessionStorage.getItem($Z.b) || ''),
		e.send(!f ? b : null), N.parentNode.dataset.load = '';
	}
	function _A(a, b, c, d, e){
		for(c in b){
			if(c in Z_){ continue; }
			_P(a, c, b[c], (!b[c]['!'] ? 0 : b[c]['!']['S'] != '0'));
		}
	}
	function _B(a, b, c, d, e, f){
		for(e in b){
			if(e in Z_){ continue; }
			_O(a, e, c, b[e], d);
		}
	}
	function _C(a, b, c, d, e){
		e = ((d && typeof d == 'object') ? d : { subtree: (!d ? true : false) }), e[b] = true,
		d = new MutationObserver(function(x, y, z){ for(y in x){ if(x[y].type == b){ c.call(x[y], x[y].target); } } }), d.observe(a, e);
	}
	function _D(a, b, c, d, e){
		_(b, 0, a).forEach(function(f){ if(_I(f, c) == d){ e = f; } });
		return e;
	}
	function _E(a, b, c, d){
		d = document.createElement(typeof c == 'string' ? c : 'a'), d.href = b, d.dataset.x = '', d.innerText = 'X', (!c ? a.insertAdjacentElement('beforebegin', d) : a.appendChild(d));
		return d;
	}
	function _F(a, b, c){
		c = (c || $Z.a);
		if(this.box){
			_('[href^="' + c + '"]', 0, this.box).forEach(function(d, e){
				if((e = d.getAttribute('href').slice(c.length)) && e in a && typeof a[e] == 'object'){ a[e].element = d; }
			});
		}
		return function(d, e, f, g, h, i, j, k, l, m, n){
			d.preventDefault();
			if(d.target.nodeName != 'A' || !(e = d.target.href) || (f = e.indexOf(c)) == -1){ return; }
			if((h = e.slice(f + c.length)) && a[h] && typeof a[h] == 'object'){
				a[h].element = d.target, n = [];

				if(a[h].extra){
					a[h].extra = (a[h].extra && typeof a[h].extra == 'object' ? a[h].extra : {});
					if(a[h].extra[0]){
						j = '';
						for(k in a[h].extra){
							l = a[h].extra[k];
							if(!(a[h].extra && typeof a[h].extra == 'object') || !l.param || (typeof l.stateFn == 'function' && l.stateFn.call(a, a[h], a[h].value, l.value))){ continue; }
							(function(l){
								n.push({
									type: 'prompt',
									text: ((typeof l.text == 'function' ? l.text.call(a, a[h], a[h].value, l.value) : l.text) || 'Valor:'),
									value: (l.value || ''),
									required: l.required,
									okFn: function(o, m){ if(m){ l.tmpValue = m, j += '&' + l.param + '=' + _J(m); } },
									cancelFn: function(){ j = ''; }
								});
							})(l);
						}
					} else {
						n.push({
							type: 'prompt',
							text: ((typeof a[h].extra.text == 'function' ? a[h].extra.text.call(a[h], a[h].value, a[h].extra.value) : a[h].extra.text) || 'Contraseña:'),
							value: (a[h].extra.value || ''),
							required: a[h].extra.required,
							okFn: function(o, g){ if(g){ j = '&' + (a[h].extra.param || 'b') + '=' + _J(g); } }
						});
					}
				}
				n.push({
					type: (i = a[h].cfm) ? 'confirm' : 'prompt',
					text: ((typeof a[h].text == 'function' ? a[h].text.call(a[h], a[h].value) : a[h].text) || a[h].element.dataset.text || (d.target.innerText + ((!a[h].element.dataset.postfix && !a[h].postfix) ? '' : (' ' + (a[h].element.dataset.postfix || a[h].postfix))) + ':')),
					value: (a[h].value || ''),
					okFn: function(o, g){
						if(g = (typeof a[h].valueFn != 'function' ? (!i ? _J(g) : '1') : a[h].valueFn.call(a[h], a[h].value, g))){
							$((e + (!a[h].siteInfo ? '?' : (_M().request + '&')) + 'a=' + g + (!j ? '' : j)),
							function(r){
								b.dataset.ok = r,
								a[h].value = (!a[h].emptyValue ? g : ''),
								(typeof a[h].ok != 'function' ? void(0) : a[h].ok.call(a[h], d.target, e));
							},
							function(e){ b.dataset.error = e, (typeof a[h].bad != 'function' ? void(0) : a[h].bad.call(a[h], d.target, e)); });
						}
					}
				});
				_Z5.apply(0, n);
			}
		}
	}
	function _G(a, b, c, d, e, f){
		f = document.createElement('a'),
		f.innerText = b,
		f[c || 'alias'] = (typeof e != 'function' ? b : e.call(f, b, d, a)),
		f.href = (!d ? ('/admin:inside:delAlias?a=' + b) : (d + b)),
		a.append(f);
		return f;
	}
	function _H(a, b){
		var c = Object.assign([], arguments), d;
		c[0] = a;
		for(d in b){ c[1] = d, _G.apply(0, c); }
	}
	function _I(a, b, c, d){
		c = 0;
		while(c < b.length){ if(!(d = (d || a)[b[c++]])){ return; } }
		return d;
	}
	function _J(a, b, c){
		if(typeof a != 'string'){ a = ''; }
		if(!a){ return a; }
		for(c in $Y){ a = a.replace(new RegExp(c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), (!b ? $Y[c] : '')); }
		return a;
	}
	function _K(){ $$ = []; }
	function _L(a, b, c, d, e){ e = _((!e ? 'a:first-child ~ a' : 'a'), 0, a), e.forEach(function(f){ a.removeChild(f); }), (typeof c != 'function' ? 0 : c.apply(0, (!d ? [a, b] : [a, b].concat(d)))); };
	function _M(a){
		a = { site: '' };
		if(O.dataset.stdSite){ a.site = O.dataset.stdSite, a.domain = O.dataset.stdSite, a.subdomain = '', a.request = ('?s=' + a.domain + '&d='); }
		if(K.dataset.stdSubdomain){ a.site = (K.dataset.stdSubdomain + '.' + a.site), a.subdomain = K.dataset.stdSubdomain, a.request += a.subdomain; }
		return a;
	}
	function _N(a, b){
		if(!b){
			a.prepend(I), a.prepend(J);
			if(a.dataset.stdSubdomain){ Q.innerText = Q.dataset.subdomainText; }
		}
		else { O.prepend(I), O.prepend(P), Q.innerText = Q.dataset.siteText; }
	}
	function _O(a, b, c, d, e, f, g, h){
		f = document.createElement('a'), f.href = ('#' + b), f[c] = (typeof e != 'function' ? function(j, k){ return { from: k, to: j } } : e).call(f, d, b),
		g = document.createElement('span'), g.innerText = b,
		h = document.createElement('i'), h.innerText = d,
		a.appendChild(f), f.append(g), f.append(h);
	}
	function _P(a, b, c, d, e){
		e = document.createElement('a');
		if(d){ e.dataset.https = ''; }
		e.site = _Q(c), e.site._ = { name: b, element: e }, e.innerText = (b || 'Raíz'), e.href = ('#' + b), a.appendChild(e);
	}
	function _Q(a, b){
		a = Object.assign({}, a);
		for(b in a){ if(a[b] && typeof a[b] == 'object'){ a[b] = Object.assign({}, a[b]); } }
		return a
	}
	function _R(c){
		(delete O.loaded), $('/admin:inside:sites', function(a, b, c, d){
			if(typeof (a = _V(a)) == 'string'){ return (N.dataset.error = a); }
			_A(L, a), $Y = {};
			for(b in a['.']){ if(b in X_ && typeof X_[b].value == 'undefined'){ X_[b].value = a['.'][b]; } }
			for(b in a['_']){
				c = a['_'][b], d = 0;
				switch(typeof c){
					case 'string': $Y[b] = c; break;
					case 'object': if(c && c['f']){ c = c['f'], $Y[b] = c, d = 1; }
				}
				_ZZ(A, b, c, d);
			}
			for(b in a['@']){ _ZY(B, b, a['@'][b]); }
			for(b in a['#']){
				c = a['#'][b], d = (c && typeof c == 'object' && c['f']),
				_ZX(C, b, (!d ? c : c['f']), d);
			}
		}, function(){ (c ? N.dataset.error = 'Actualice la página' : _R(1)); });
	}
	function _S(e, f){
		$(('/admin:inside:subdomains?s=' + e.site._.name), function(a, b){
			if(typeof (a = _V(a)) == 'string'){ return (N.dataset.error = a); }
			e.site = Object.assign(e.site, a), O.loaded[e.site._.name] = 1,
			O.dataset.stdSite = e.site._.name, O.site = e.site;
		}, function(a){ (f ? N.dataset.error = a : _S(e, 1)); });
	}
	function _T(e, f){
		$(('/admin:inside:subdomainData?s=' + O.dataset.stdSite + '&d=' + e.site._.name), function(a, b){
			if(typeof (a = _V(a)) == 'string'){ return (N.dataset.error = a); }
			e.site = Object.assign(e.site, a), O.loaded[e.site._.name + '.' + O.dataset.stdSite] = 1,
			K.subdomain = e.site, K.dataset.stdSubdomain = e.site._.name;
		}, function(a){ (f ? N.dataset.error = a : _T(e, 1)); });
	}
	function _U(a){ return (a.indexOf('data-err') != -1 ? 'Vuelva a entrar' : (!a ? 'Vuelva a intentarlo' : (a.indexOf('<meta') != -1 ? 'Inautorizado' : null))); }
	function _V(a){
		try { a = JSON.parse(a); }
		catch(a){ return 'Contenido incorrecto'; }
		if(!Object.keys(a).length){ return 'Contenido vacío'; }
		return a;
	}
	function _W(a, b, c, d, e){
		e = {};
		for(d in b){
			if(!c[d] || typeof c[d] != 'object' || !c[d].element){ continue; }
			if(typeof c[d].setting == 'function'){ e[d] = 1; }
			try { c[d].value = decodeURIComponent(b[d]); }
			catch(__e){ c[d].value = self['unescape'] ? unescape(b[d]) : b[d]; }
		}
		for(d in e){ c[d].setting(b[d]); }
	}
	function _X(d, e){
		return {
			cfm: true,
			siteInfo: true,
			text: _Y,
			valueFn: _Z,
			ok: function(a, b){ a = _M(), b = O.site[a.subdomain], b['!'][d] = this.value, this.setting(this.value); },
			setting: function(a, b, c){
				b = _M(), c = b.subdomain && b.subdomain != 'www', _Z0.call(this, a);
				if(a != '0' || c){ W_[e].element.parentNode.dataset.hidden = '' }
				else { (delete W_[e].element.parentNode.dataset.hidden); }
				if(W_[e].value != '0' || c){ this.element.parentNode.dataset.hidden = ''; }
				else { (delete this.element.parentNode.dataset.hidden); }
			}
		}
	}
	function _Y(a){ return (this.element.dataset[(a != '0' ? 'false' : 'true') + 'Text']); }
	function _Z(a){ return (a != '0' ? '0' : '1'); }
	function _Z0(a){ this.element.innerText = this.element.dataset[a != '0' ? 'false' : 'true']; }
	function _Z1(a, b){
		_C(a, 'childList', function(){
			if(this.addedNodes.length){
				this.addedNodes.forEach(function(i){
					if(i.nodeName != 'A'){ return; }
					i.onclick = function(c){
						if(typeof c.target.dataset.x != 'undefined'){ return; }
						a.firstElementChild.onclick.call(i, c, i[b.key], i[b.value]);
					};
					if(!i.firstElementChild){ return; }
					i.firstElementChild.onclick = function(c, d, e, f){
						c.preventDefault(), f = this;
						_Z4('confirm', {
							text: b.text.replace('{REFERENCE}', i[b.key]),
							okFn: function(){ d = f.href.indexOf('#'), $(((d != -1 ? f.href.substring(0, d) : f.href) + '?s=' + _J(i[b.key])), function(r){ N.dataset.ok = r, (typeof b.okFn == 'function' ? b.okFn.call(i, i[b.key], i[b.value]) : a.removeChild(i)); }, function(e){ N.dataset.error = e; }); }
						});
					};
				});
			}
		});
	}
	function _Z2(a, b){
		clearTimeout(a._t), b = _Z3(b);
		if(b > 7200){ return; } // Like 2 hours
		a._t = setTimeout(function(){
			a.parentNode.removeChild(a);
		}, b);
	}
	function _Z3(a, b){
		a = new Date(a * 1000).getTime(), b = (new Date).getTime();
		return (a <= b ? 0 : a - b);
	}
	function _Z4(a, b, c, d, e, f, g, h, i, j, k){
		k = a == 'prompt',
		h = document.createElement('article'), document.body.appendChild(h),
		i = document.createElement('div'), h.appendChild(i),
		c = document.createElement('span'), i.appendChild(c),
		d = document.createElement('button'), d.innerText = b.cancelText || (!k ? 'No' : 'Cancelar'), c.appendChild(d),
		e = document.createElement('button'), e.innerText = b.okText || (!k ? 'Sí' : 'Aceptar'), e.dataset.first = '', c.appendChild(e);
		if(b.assign && typeof b.assign == 'object'){ for(j in b.assign){ h[j] = b.assign[j]; } }
		if(b.text){ f = document.createElement('p'), f.innerText = b.text, i.prepend(f); }
		if(k){
			g = document.createElement('input'),
			g.type = 'text',
			g.placeholder = b.placeholder || '',
			g.value = b.value || '',
			(!f ? i.prepend(g) : f.insertAdjacentElement('afterend', g)), g.focus();
		}
		h.onclick = function(j){ if(j.target.nodeName == 'ARTICLE'){ d.click(); } }
		d.onclick = function(){
			g = (!g ? null : g.value), (typeof b.cancelFn == 'function' ? b.cancelFn.call(h, b, g) : 0), document.body.removeChild(h);
			(!b.required && b.next && typeof b.next == 'object' ? (b.next.previous = b, b.next.previous.finalValue = g, _Z4(b.next.type, b.next)) : 0);
		}
		e.onclick = function(){
			if(g && b.required && !g.value && b.strict !== false){ return g.focus(); }
			g = (!g ? null : g.value), (typeof b.okFn == 'function' ? b.okFn.call(h, b, g) : 0), document.body.removeChild(h);
			(b.next && typeof b.next == 'object' ? (b.next.previous = b, b.next.previous.finalValue = g, _Z4(b.next.type, b.next)) : 0);
		}
	}
	function _Z5(){
		var a = 0;
		for(; a < arguments.length; a++){ arguments[a].type = arguments[a].type || 'prompt', arguments[a].next = arguments[a + 1]; }
		if(arguments.length && !arguments[a - 1].next){ delete arguments[a - 1].next; }
		_Z4(arguments[0].type, arguments[0]);
	}
	function _ZZ(a, b, c, d, e){
		e = document.createElement('a');
		e.chars = b, e.replacement = c, e.innerText = b, e.href = ('/admin:inside:addCharsReplace#' + b),
		a.appendChild(e), (!d ? _E(e, '/admin:inside:delCharsReplace', 'span') : 0);
	}
	function _ZY(a, b, c, d){
		d = document.createElement('a');
		d.ip = b, d.unblockingDate = c, d.innerText = b, d.href = ('/admin:inside:addDenied#' + b),
		a.appendChild(d), _E(d, '/admin:inside:delDenied', 'span'),	_Z2(d, c);
	}
	function _ZX(a, b, c, d, e){
		e = document.createElement('a'),
		e.httpCode = b, e.response = c, e.innerText = (b == '0' ? 'Por defecto' : b), e.href = ('/admin:inside:addHttpCodeResponse#' + b),
		a.appendChild(e), (!d ? _E(e, '/admin:inside:delHttpCodeResponse', 'span') : 0);
	}

	D = _('#Q', 1),
	E = _('#B', 1),
	F = _('#N', 1),
	G = _('#I > a:first-child', 1),
	H = _('#J > a:first-child', 1),
	I = _('#T + ul', 1),
	J = _('#R > a:first-child', 1),
	K = _('#R', 1),
	L = _('#A', 1),
	A = _('#P', 1),
	B = _('#K', 1),
	C = _('#X', 1),
	M = _('aside', 1),
	N = _('header > p', 1),
	O = _('main', 1),
	P = _('#T', 1),
	Q = _('#D', 1),
	R = _('#U', 1),
	S = _('#O input', 1),
	T = _('#S > a:first-child', 1),
	U = _('#W > a:first-child', 1),
	V = _('#M > a:first-child', 1),
	W = _('#H > a:first-child', 1),
	X = _('#G', 1),
	Y = _('#L', 1),
	Z = _('#Z > a:first-child', 1),
	U_ = _('fieldset legend'),
	T_ = _('[href="/admin:signout:"]', 1);

	Z_ = { '#': {}, '@': {}, '_': {}, '.': {}, '!': {}, '$': {}, '&': {}, '?': {}, '-': {}, '=': {} },
	Y_ = {
		'S': function(a, i){
			O.site[i.site._.name] = i.site, i.onclick = function(a){
				a.preventDefault();
				if(!O.loaded[this.site._.name + '.' + O.dataset.stdSite]){ return _T(this); }
				K.subdomain = this.site, K.dataset.stdSubdomain = this.site._.name;
			};
		},
		'Z': function(a, i){
			i.onclick = function(b, c, d, e){
				b.preventDefault(), c = _M(), e = this, d = e.alias;
				_Z4('confirm', {
					text: '¿Borrar el alias "' + d + '" de "' + c.site + '"?',
					okFn: function(){ $((e.href + '&s=' + c.domain + '&d=' + c.subdomain), function(r){ N.dataset.ok = r, a.removeChild(i), (delete O.site[c.subdomain]['&'][d]); }, function(e){ N.dataset.error = e; }); }
				});
			};
		},
		'W': function(a, i, j, k, l){
			j = _E(i, '/admin:inside:delRewrite'), k = i.rewrite.from, l = i.rewrite.to,
			j.onclick = function(b){
				b.preventDefault();
				_Z4('confirm', { text: '¿Borrar la reescritura "' + k + '" a "' + l + '"?', okFn: function(){ $((j.href + _M().request + '&a=' + _J(k)), function(r){ N.dataset.ok = r, (delete K.subdomain['='][k]), a.removeChild(i), a.removeChild(j), _K(); }, function(e){ N.dataset.error = e, _K(); }); }});
			}, i.onclick = function(b){ b.preventDefault(), $$[0] = k, $$[1] = l, U.onclick.call(this); };
		},
		'M': function(a, i, j, k, l){
			j = _E(i, '/admin:inside:delMIME'), k = i.mime.from, l = i.mime.to,
			j.onclick = function(b){
				b.preventDefault();
				_Z4('confirm', { text: '¿Borrar el MIME "' + k + '" con "' + l + '"?', okFn: function(){ $((j.href + _M().request + '&a=' + k), function(r){ N.dataset.ok = r, (delete K.subdomain['$'][k]), a.removeChild(i), a.removeChild(j), _K(); }, function(e){ N.dataset.error = e, _K(); }); }});
			}, i.onclick = function(b){ b.preventDefault(), $$[0] = k, $$[1] = l, V.onclick.call(this); };
		},
		'H': function(a, i, j, k, l){
			j = _E(i, '/admin:inside:delHeader'), k = i.header.name, l = i.header.content,
			j.onclick = function(b){
				b.preventDefault();
				_Z4('confirm', { text: '¿Borrar la cabecera "' + k + '" con "' + l + '"?', okFn: function(){ $((j.href + _M().request + '&a=' + k), function(r){ N.dataset.ok = r, (delete K.subdomain['.'][k]), a.removeChild(i), a.removeChild(j), _K(); }, function(e){ N.dataset.error = e, _K(); }); }});
			}, i.onclick = function(b){ b.preventDefault(), $$[0] = k, $$[1] = l, W.onclick.call(this); };
		},
		'J': function(a, i, j, k, l){
			j = _E(i, '/admin:inside:delPreprocessor'), k = i.preprocessor.from, l = i.preprocessor.to,
			j.onclick = function(b){
				b.preventDefault();
				_Z4('confirm', { text: '¿Borrar el preprocesador para "' + k + '" con "' + l + '"?', okFn: function(){ $((j.href + _M().request + '&a=' + k), function(r){ N.dataset.ok = r, (delete K.subdomain['?'][k]), a.removeChild(i), a.removeChild(j), _K(); }, function(e){ N.dataset.error = e, _K(); }); }});
			}, i.onclick = function(b){ b.preventDefault(), $$[0] = k, $$[1] = l, H.onclick.call(this); };
		},
		'I': function(a, i, j, k, l){
			j = _E(i, '/admin:inside:delIndex'), k = i.index, l = _M(),
			j.onclick = function(b){
				b.preventDefault();
				_Z4('confirm', { text: '¿Borrar el índice "' + k + '" de "' + l.site + '"?', okFn: function(){ $((j.href + l.request + '&a=' + _J(k)), function(r){ N.dataset.ok = r, (delete K.subdomain['-'][k]), a.removeChild(i), a.removeChild(j), _K(); }, function(e){ N.dataset.error = e, _K(); }); }});
			}, i.onclick = function(b){ b.preventDefault(), $$[0] = k, G.onclick.call(this); };
		}
	},
	X_ = { 'U': { extra: { value: '', required: 1 } }, 'P': { extra: { value: '', required: 1 } }, 'C': { cfm: true, emptyValue: true }, 'RHT': {}, 'RT': {}, 'WT': {}, 'IT': {}, 'CII': {}, 'MUB': {}, 'MHB': {}, 'MBB': {}, 'CIS': {}, 'CIL': {} },
	X_['M'] = { ok: function(a){ _L(L), _L(A), _L(B), _L(C), _R(); } },
	X_['U'].extra.text = X_['P'].extra.text = 'Contraseña actual:',
	X_['RHT'].postfix = X_['RT'].postfix = X_['WT'].postfix = X_['IT'].postfix = '(milisegundos [ms], segundos [s], minutos [m], e ilimitado [0])',
	X_['MUB'].postfix = X_['MHB'].postfix = X_['MBB'].postfix = '(bytes)',
	D.onclick = _F(X_, N), F.onclick = _F(X_, N), X.onclick = _F(X_, N), Y.onclick = _F(X_, N);
	W_ = {
		'S': {
			cfm: true,
			siteInfo: true,
			text: _Y,
			valueFn: _Z,
			ok: function(a, b){
				a = _M(), b = O.site[a.subdomain], b['!']['S'] = this.value, this.setting(this.value);
				if(this.value != '0'){
					if(!a.subdomain){ O.site._.element.dataset.https = ''; }
					b._.element.dataset.https = '';
				}
				else {
					if(!a.subdomain){ (delete O.site._.element.dataset.https); }
					(delete b._.element.dataset.https);
				}
			},
			setting: _Z0
		},
		'W': _X('W', 'R'),
		'R': _X('R', 'W'),
		'E': {
			element: true,
			param: 'z',
			text: 'E-mail:',
			stateFn: function(a, b, c){ if(((c = a.wait.list[_M().site]) && c.status) || a.wait.filter(b) != '0'){ return true; } },
			tmpValue: '',
			required: 1
		},
		'A': {
			element: true,
			param: 'y',
			text: 'Adaptador (opcional [dns-route53, etc.]):',
			tmpValue: ''
		}, 
		'C': {
			cfm: true,
			siteInfo: true,
			text: function(a, b){
				if((b = this.wait.list[_M().site]) && b.status){ return this.element.dataset.waitText; }
				return _Y.call(this, this.wait.filter(a));
			},
			valueFn: function(a){ return _Z.call(this, this.wait.filter(a)); },
			ok: function(a){
				a = _M().subdomain,
				O.site[a]['!']['C'] = this.value,
				O.site[a]['!']['E'] = W_['E'].tmpValue,
				O.site[a]['!']['A'] = W_['A'].tmpValue, this.wait.setFalse();
			},
			bad: function(a, b){
				a = _M().subdomain,
				O.site[a]['!']['E'] = W_['E'].tmpValue,
				O.site[a]['!']['A'] = W_['A'].tmpValue;
				return this.wait['set' + (new RegExp('Espere').test(b) ? 'True' : 'False')]();
			},

			setting: function(a, b){ // Maybe this.setting can be used as automatic after this.ok
				b = _M().site, this.wait.list[b] = this.wait.list[b] || {};
				if(typeof this.wait.list[b].startValue == 'undefined'){ this.wait.list[b].startValue = a; }
				if(this.wait.list[b].status || (typeof this.wait.list[b].startValue == 'string' && this.wait.condition(this.wait.list[b].startValue))){
					this.wait.list[b].status = true, this.element.innerText = this.element.dataset.wait, this.element.dataset.loadLink = '';
					return;
				}
				(delete this.element.dataset.loadLink);
				return _Z0.call(this, this.wait.filter(a));
			},

			wait: {
				list: {},
				setFalse: function(a){ a = _M().site, this.list[a].startValue = false, this.list[a].status = false, W_.C.setting(W_.C.value); },
				setTrue: function(){
					var a = _M().site;
					this.list[a].startValue = false, this.list[a].status = true, W_.C.setting(W_.C.value);
				},
				filter: function(a){ return (this.condition(a) ? '0' : a); },
				condition: function(a){ return a != '0' && a != '1'; }
			}
		}
	},
	V_ = {};
	W_['C'].extra = [W_['E'], W_['A']], W_['A'].stateFn = W_['E'].stateFn;
	document.ondragstart = function(a){ return a.preventDefault(); },
	document.onselectstart = function(a){ return a.preventDefault(); },
	(function(a, b, c, d){
		a = self.location.search.indexOf('?' + $Z.b),
		c = (a != -1 ? self.location.search.slice(a) : ''),
		(c ? sessionStorage.setItem($Z.b, (($W = c.indexOf('&')) != -1 ? c.substring($Z.b.length + 1, $W) : c.slice($Z.b.length + 1))) : 0);
	})(),
	E.onclick = _F.call({ box: E }, W_, N, '/admin:inside:cfg');
	J.onclick = function(a){
		if(a){ a.preventDefault(); } // For trigger with no context
		_N(0, 1), (delete K.dataset.stdSubdomain);
	};
	L.firstElementChild.onclick = function(b, c, d){
		b.preventDefault(), d = this;
		_Z4('prompt', { text: 'Dominio:', required: true, okFn: function(z, c){ $((d.href + '?s=' + c), function(r){ N.dataset.ok = r, _P(L, c, { '': Z_ }, 0); }, function(e){ N.dataset.error = e; }); }});
	};
	A.firstElementChild.onclick = function(b, c, d, e, f, g, h){
		b.preventDefault(), f = this, h = [];
		if(!c){
			h.push({ 
				type: 'prompt',
				text: 'Caracter(es):',
				required: true
			});
		}
		h.push({
			type: 'prompt',
			text: 'Reemplazo:',
			required: true,
			value: d || '',
			okFn: function(z, d){
				c = (!c ? z.previous.finalValue : c), e = f.href.indexOf('#'),
				$(((e != -1 ? f.href.substring(0, e) : f.href) + '?s=' + _J(c) + '&d=' + _J(d)), function(r){
					N.dataset.ok = r, (f.chars != c ? _ZZ(A, c, d) : f.replacement = d), $Y[c] = d;
				}, function(e){ N.dataset.error = e; });
			}
		});
		_Z5.apply(0, h);
	};
	B.firstElementChild.onclick = function(b, c, d, e, f, g, h){
		b.preventDefault(), h = [], f = ' ' + (d && !isNaN(d) ? new Date(d * 1000).toLocaleString() : '(este instante: ' + Math.ceil((new Date).getTime() / 1000) + ')'), g = this;
		if(!c){
			h.push({
				type: 'prompt',
				text: 'IPv4 / IPv6:',
				required: true
			});
		}
		h.push({
			type: 'prompt',
			text: 'Fecha UNIX de desbloqueo' + f +  ':',
			required: true,
			value: d || '',
			okFn: function(z, d){
				c = (!c ? z.previous.finalValue : c), e = g.href.indexOf('#'),
				$(((e != -1 ? g.href.substring(0, e) : g.href) + '?s=' + c + '&d=' + d), function(r){
					N.dataset.ok = r, (g.ip != c ? _ZY(B, c, d) : (g.unblockingDate = d, _Z2(g, d)));
				}, function(e){ N.dataset.error = e; });
			}
		});
		_Z5.apply(0, h);
	};
	C.firstElementChild.onclick = function(b, c, d, e, f, g){
		b.preventDefault(), f = this, g = [];
		if(!c){
			g.push({
				type: 'prompt',
				text: 'Código HTTP:',
				required: true
			});
		}
		g.push({
			type: 'prompt',
			text: 'Respuesta:',
			required: true,
			value: d || '',
			okFn: function(z, d){
				c = (!c ? z.previous.finalValue : c), e = f.href.indexOf('#'),
				$(((e != -1 ? f.href.substring(0, e) : f.href) + '?s=' + c + '&d=' + _J(d)), function(r){
					N.dataset.ok = r, (f.httpCode != c ? _ZX(C, c, d) : f.response = d);
				}, function(e){ N.dataset.error = e; });
			},
			assign: { className: 'B' }
		});
		_Z5.apply(0, g);
	};
	N.onclick = function(){ this.innerText = '', (delete this.dataset.ok), (delete this.dataset.error), (delete this.dataset.largeOk), (delete this.dataset.largeError); };
	P.onclick = function(a){
		if(a){ a.preventDefault(); }
		J.onclick(), (delete O.dataset.stdSite);
	};
	Q.onclick = function(a, b, c){
		a.preventDefault(), b = _M(), c = this;
		_Z4('confirm', {
			text: '¿Borrar definitivamente "' + b.site + '"?',
			okFn: function(){
				$((c.href + b.request), function(r, s){
					N.dataset.ok = r;
					if(typeof K.dataset.stdSubdomain != 'undefined' && (s = K.subdomain._.name)){ (delete O.site[s]), T.parentNode.removeChild(K.subdomain._.element); return J.onclick(); }
					P.onclick(), L.removeChild(O.site._.element);
				}, function(e){ N.dataset.error = e; });
			}
		});
	};
	R.onclick = function(a){
		a.preventDefault(),
		S['webkitdirectory'] = true,
		S['mozdirectory'] = true,
		S.click();
	};
	S.addEventListener('change', function(a, b){
		a = _M(), b = this;
		_Z4('confirm', {
			text: '¿Borrar y subir datos a "' + a.site + '"?',
			okFn: function(){
				$((R.href + a.request), new FormData(b.parentNode), function(r){ N.dataset.ok = r, S.parentNode.reset(); }, function(e){ N.dataset.error = e, S.parentNode.reset(); });
			}
		});
	});
	T.onclick = function(a, b, c){
		a.preventDefault();
		_Z4('prompt', {
			text: 'Subdominio:',
			required: true,
			okFn: function(z, c){
				$((T.href + '?s=' + O.dataset.stdSite + '&d=' + c), function(r){ N.dataset.ok = r, _P(T.parentNode, c, Z_, 0); }, function(e){ N.dataset.error = e; });
			}
		});
	};
	Z.onclick = function(b, c, d, e, f){
		b.preventDefault(), f = this;
		_Z4('prompt', {
			text: 'Alias:',
			required: true,
			okFn: function(z, c){
				e = _M(), $((f.href + e.request + '&a=' + c), function(r){ N.dataset.ok = r, _G(Z.nextElementSibling, c), O.site[e.subdomain]['&'][c] = ''; }, function(e){ N.dataset.error = e; });
			}
		});
	};
	U.onclick = function(a, b, c, d, e){
		if(a){ a.preventDefault(); }
		d = this, _Z5({
			text: 'Dirección relativa (/...):',
			value: $$[0] || '',
			required: true,
			cancelFn: _K
		}, {
			text: 'Reescribir (/...) o redirigir (https://...) a:',
			value: $$[1] || '',
			required: true,
			okFn: function(z, c){
				b = z.previous.finalValue,
				b = ((b.charAt(0) != '/' ? '/' : '') + b),
				c = ((c.charAt(0) != '/' ? (!/https?\:\/\//.test(c) ? '/' : '') : '') + c),
				e = 'rewrite',
				$((U.href + _M().request + '&a=' + _J(b) + '&b=' + _J(c)), function(r, s, t, u){
					if(b in K.subdomain['=']){ t = _D(U.nextElementSibling, 'a', [e, 'from'], b); }
					N.dataset.ok = r, K.subdomain['='][b] = c, _O(U.nextElementSibling, b, e, c);
					if($$[0]){
						if(b != d[e].from){ _K(); return d.previousSibling.click(); }
						U.nextElementSibling.removeChild(d.previousSibling), U.nextElementSibling.removeChild(d), u = 1;
					}
					if(!u && t){ U.nextElementSibling.removeChild(t.previousSibling), U.nextElementSibling.removeChild(t); }
					_K();
				}, function(g){ N.dataset.error = g, _K(); });
			},
			cancelFn: _K
		});
	};
	V.onclick = function(a, b, c, d, e){
		if(a){ a.preventDefault(); }

		d = this, _Z5({
			text: 'Extensión:',
			value: $$[0] || '',
			required: true,
			strict: false,
			cancelFn: _K
		},{
			text: 'Asignar MIME:',
			value: $$[1] || '',
			required: true,
			okFn: function(z, c){
				b = z.previous.finalValue,
				b = _J((b.charAt(0) != '.' ? b : b.slice(1)), 1),
				e = 'mime',
				$((V.href + _M().request + '&a=' + b + '&b=' + _J(c)), function(r, s, t, u){
					if(b in K.subdomain['$']){ t = _D(V.nextElementSibling, 'a', [e, 'from'], b); }
					N.dataset.ok = r, K.subdomain['$'][b] = c, _O(V.nextElementSibling, b, e, c);
					if($$[0] != null){
						if(b != d[e].from){ _K(); return d.previousSibling.click(); }
						V.nextElementSibling.removeChild(d.previousSibling), V.nextElementSibling.removeChild(d), u = 1;
					}
					if(!u && t){ V.nextElementSibling.removeChild(t.previousSibling), V.nextElementSibling.removeChild(t); }
					_K();
				}, function(g){ N.dataset.error = g, _K(); });
			},
			cancelFn: _K
		});
	};
	W.onclick = function(a, b, c, d, e){
		if(a){ a.preventDefault(); }

		d = this, _Z5({
			text: 'Cabecera:',
			value: $$[0] || '',
			required: true,
			cancelFn: _K
		},{
			text: 'Contenido:',
			value: $$[1] || '',
			required: true,
			okFn: function(z, c){
				b = z.previous.finalValue,
				b = _J(b, 1), e = 'header',
				$((W.href + _M().request + '&a=' + b + '&b=' + _J(c)), function(r, s, t, u){
					if(b in K.subdomain['.']){ t = _D(W.nextElementSibling, 'a', [e, 'name'], b); }
					N.dataset.ok = r, K.subdomain['.'][b] = c, _O(W.nextElementSibling, b, e, c, function(a, b){ return { name: b, content: a } });
					if($$[0] != null){
						if(b != d[e].name){ _K(); return d.previousSibling.click(); }
						W.nextElementSibling.removeChild(d.previousSibling), W.nextElementSibling.removeChild(d), u = 1;
					}
					if(!u && t){ W.nextElementSibling.removeChild(t.previousSibling), W.nextElementSibling.removeChild(t); }
					_K();
				}, function(g){ N.dataset.error = g, _K(); });
			},
			cancelFn: _K
		});
	};
	H.onclick = function(a, b, c, d, e){
		if(a){ a.preventDefault(); }
		d = this, _Z5({
			text: 'Extensión:',
			value: $$[0] || '',
			required: true,
			strict: false,
			cancelFn: _K
		},{
			text: 'Ruta del preprocesador:',
			value: $$[1] || '',
			required: true,
			okFn: function(z, c){
				b = z.previous.finalValue,
				b = _J((b.charAt(0) != '.' ? b : b.slice(1)), 1),
				e = 'preprocessor',
				$((H.href + _M().request + '&a=' + b + '&b=' + _J(c)), function(r, s, t, u){
					if(b in K.subdomain['?']){ t = _D(H.nextElementSibling, 'a', [e, 'from'], b); }
					N.dataset.ok = r, K.subdomain['?'][b] = c, _O(H.nextElementSibling, b, e, c);
					if($$[0] != null){
						if(b != d[e].from){ _K(); return d.previousSibling.click(); }
						H.nextElementSibling.removeChild(d.previousSibling), H.nextElementSibling.removeChild(d), u = 1;
					}
					if(!u && t){ H.nextElementSibling.removeChild(t.previousSibling), H.nextElementSibling.removeChild(t); }
					_K();
				}, function(g){ N.dataset.error = g, _K(); });
			},
			cancelFn: _K
		});
	};
	G.onclick = function(a, b, c, d, e){
		if(a){ a.preventDefault(); }
		d = this, _Z4('prompt', {
			text: 'Archivo de índice:',
			value: $$[0] || '',
			okFn: function(z, b){
				e = 'index',
				$((G.href + _M().request + '&a=' + _J(b)), function(s, t, u){
					t = (b in K.subdomain['-'] ? _D(G.nextElementSibling, 'a', [e], b) : 0),
					N.dataset.ok = s, K.subdomain['-'][b] = '', _G(G.nextElementSibling, b, e, '#');
					if($$[0] != null){
						if(b != d[e]){ _K(); return d.previousSibling.click(); }
						G.nextElementSibling.removeChild(d.previousSibling), G.nextElementSibling.removeChild(d), u = 1;
					}
					if(!u && t){ G.nextElementSibling.removeChild(t.previousSibling), G.nextElementSibling.removeChild(t); }
					_K();
				}, function(g){ N.dataset.error = g, _K(); });
			},
			cancelFn: _K
		});
	};
	U_.forEach(function(a, b){
		b = a.nextElementSibling,
		a.onclick = function(){
			if(typeof b.dataset.hidden == 'undefined'){ return b.dataset.hidden = '', (delete a.dataset.std); }
			delete b.dataset.hidden, a.dataset.std = '';
		}
	});
	T_.onclick = function(a){
		if(a){ a.preventDefault(); }
		$('/admin:signout:' /* + '?' + sessionStorage.getItem($Z.b) // Delete all per IP sessions */), N.dataset.ok = '. . .',
		setTimeout(function(){ sessionStorage.removeItem($Z.b), self.location.reload(); }, 567);
	};
	self.onkeydown = function(a, b){
		b = _('article [data-first]'), b = b[b.length - 1];
		if(!b){ return; }
		switch(a.key){
			case 'Escape': b.previousElementSibling.click(); break;
			case 'Enter': b.focus(), b.click(); break;
		}
	};
	_C(O, 'childList', function(a, b){
		if(this.addedNodes.length){
			if(!(b = (a.id || a.parentNode.id))){ return; }
			if(b in Y_){ this.addedNodes.forEach(function(c){ if(c.nodeName == 'A' && typeof c.dataset.x == 'undefined'){ Y_[b](a, c); } }); }
		}
	});
	_C(O, 'attributes', function(a){
		if(a.nodeName == 'MAIN' && this.attributeName == 'data-std-site'){
			if(a.site && a.dataset.stdSite == a.site._.name){
				M.dataset.hidden = '', P.innerText = a.site._.name, 
				_L(T.parentNode, a.site, _A),
				_L(Z.nextElementSibling, a.site['']['&'], _H, 0, 1),
				_W(E, a.site['']['!'], W_);
			}
			else { (delete M.dataset.hidden), (delete a.dataset.stdSite); }
		}
		if(a.id == 'R' && this.attributeName == 'data-std-subdomain'){
			if(a.subdomain && a.dataset.stdSubdomain == a.subdomain._.name){
				_N(a), T.parentNode.dataset.hidden = '', J.innerText = (a.subdomain._.name || 'Raíz'),
				_L(Z.nextElementSibling, a.subdomain['&'], _H, 0, 1);
				_L(U.nextElementSibling, a.subdomain['='], _B, ['rewrite'], 1),
				_L(V.nextElementSibling, a.subdomain['$'], _B, ['mime'], 1),
				_L(W.nextElementSibling, a.subdomain['.'], _B, ['header', function(a, b){ return { name: b, content: a } }], 1),
				_L(H.nextElementSibling, a.subdomain['?'], _B, ['preprocessor'], 1),
				_L(G.nextElementSibling, a.subdomain['-'], _H, ['index', '#'], 1),
				_W(E, a.subdomain['!'], W_);
			}
			else {
				_N(a, 1), (delete T.parentNode.dataset.hidden), (delete a.dataset.stdSubdomain),
				_L(Z.nextElementSibling, O.site['']['&'], _H, 0, 1),
				_W(E, O.site['']['!'], W_);
			}
		}
	});
	_C(N, 'attributes', function(a){
		if(this.attributeName == 'data-error' && a.dataset.error){
			if(a.dataset.error.length > 50 || self.scrollY != 0){ a.dataset.largeError = ''; }
			clearTimeout(N.T), (delete a.dataset.ok), console.error(a.dataset.error), a.innerText = a.dataset.error, N.T = setTimeout(function(){ a.onclick(), (delete a.dataset.largeError); }, 7890);
		}
		if(this.attributeName == 'data-ok' && a.dataset.ok){
			if(a.dataset.ok.length > 50 || self.scrollY != 0){ a.dataset.largeOk = ''; }
			clearTimeout(N.T), (delete a.dataset.error), a.innerText = a.dataset.ok, N.T = setTimeout(function(){ a.onclick(), (delete a.dataset.largeOk); }, 7890);
		}
	}, 1);
	_C(L, 'childList', function(){
		if(this.addedNodes.length){
			this.addedNodes.forEach(function(i){
				if(i.nodeName == 'A'){
					i.onclick = function(a){
						a.preventDefault();
						if(!O.loaded){ O.loaded = {}; }
						if(!O.loaded[this.site._.name]){ return _S(this); }
						O.dataset.stdSite = this.site._.name, O.site = this.site;
					};
				}
			});
		}
	});
	_Z1(A, { key: 'chars', value: 'replacement', text: '¿Borrar reemplazo de caracter "{REFERENCE}"?' });
	_Z1(B, { key: 'ip', value: 'unblockingDate', text: '¿Borrar IP denegado "{REFERENCE}"?' });
	_Z1(C, { key: 'httpCode', value: 'response', text: '¿Borrar respuesta a código HTTP "{REFERENCE}"?' });
	_R(), _K();
});
</script>
</head>
<body>
	<header>
		<h1><img src="/admin:i.png" alt="Logotipo de OKZGN"></h1>
		<h2>Turbo</h2>
		<p></p>
		<a target="_blank" href="https://okzgn.com"><span>Ayuda</span></a>
		<a href="/admin:signout:"><span>Salir</span></a>
	</header>
	<aside>
		<fieldset id="N">
			<legend>Configuración general</legend>
			<ul data-hidden>
				<li><a href="/admin:inside:setU">Cambiar usuario</a></li>
				<li><a href="/admin:inside:setP">Cambiar contraseña</a></li>
				<li><a href="/admin:inside:setM">Directorio de sitios</a></li>
				<li><a data-text="¿Guardar rescribiendo configuración?" href="/admin:inside:setC">Guardar configuración</a></li>
			</ul>
		</fieldset>
		<fieldset id="L">
			<legend>Frecuencia de peticiones</legend>
			<ul data-hidden>
				<li><a data-postfix="(milisegundos [ms])" href="/admin:inside:setCIS">Contador de peticiones por intervalo</a></li>
				<li><a href="/admin:inside:setCII">Peticiones máximas por intervalo</a></li>
				<li><a data-postfix="(milisegundos [ms])" href="/admin:inside:setCIL">Tiempo de reinicio de contador</a></li>
			</ul>
		</fieldset>
		<fieldset id="G">
			<legend>Tiempo para cada petición</legend>
			<ul data-hidden>
				<li><a href="/admin:inside:setRHT">Lectura de cabeceras</a></li>
				<li><a href="/admin:inside:setRT">Lectura total de petición</a></li>
				<li><a href="/admin:inside:setWT">Escritura de respuesta</a></li>
				<li><a href="/admin:inside:setIT">Cierre de conexión inactiva</a></li>
			</ul>
		</fieldset>
		<fieldset id="Q">
			<legend>Límites para cada petición</legend>
			<ul data-hidden>
				<li><a href="/admin:inside:setMUB">Tamaño máx. de <i>URIs</i></a></li>
				<li><a href="/admin:inside:setMHB">Tamaño máx. de cabeceras</a></li>
				<li><a href="/admin:inside:setMBB">Tamaño máx. de contenidos</a></li>
			</ul>
		</fieldset>
		<section id="A">
			<a class="O" href="/admin:inside:addSite">Agregar sitio</a>
		</section>
		<section id="K">
			<a class="O" href="/admin:inside:addDenied">Agregar IP denegado</a>
		</section>
		<section id="X">
			<a class="O" href="/admin:inside:addHttpCodeResponse">Agregar respuesta a código HTTP</a>
		</section>
		<section id="P">
			<a class="O" href="/admin:inside:addCharsReplace">Agregar reemplazo de caracter(es)</a>
		</section>
	</aside>
	<main>
		<form id="O"><input type="file" name="f" multiple webkitdirectory mozdirectory></form>
		<a id="T" class="F" href="/admin:inside:"></a>
		<ul id="B">
			<li><a data-true-text="¿Generar certificado SSL?" data-false-text="¿Eliminar certificado SSL?" data-wait-text="¿Obtener respuesta del certificado?" data-true="Crear SSL" data-false="Borrar SSL" data-wait="Respuesta SSL" href="/admin:inside:cfgC">Crear SSL</a></li>
			<li><a data-true-text="¿Activar redirección HTTPS?" data-false-text="¿Desactivar redirección HTTPS?" data-true="R. HTTPS" data-false="Sin r. HTTPS" href="/admin:inside:cfgS">R. HTTPS</a></li>
			<li><a data-true-text="¿Activar redirección desde raíz a www?" data-false-text="¿Desactivar redirección desde raíz a www?" data-true="R. www" data-false="Sin r. www" href="/admin:inside:cfgW">R. www</a></li>
			<li><a data-true-text="¿Activar redirección desde www a raíz?" data-false-text="¿Desactivar redirección desde www a raíz?" data-true="R. raíz" data-false="Sin r. raíz" href="/admin:inside:cfgR">R. raíz</a></li>
			<li><a id="U" href="/admin:inside:hardUpload">Subir archivos</a></li>
			<li><a id="D" data-site-text="Borrar sitio" data-subdomain-text="Borrar subdominio" href="/admin:inside:delSite">Borrar sitio</a></li>
		</ul>
		<section id="Z">
			<a class="O" href="/admin:inside:addAlias">Agregar alias</a>
			<div class="L"></div>
		</section>
		<section id="S"><a class="O" href="/admin:inside:addSubdomain">Agregar subdominio</a></section>
		<section id="R">
			<a class="F" href="/admin:inside:"></a>
			<div id="M" class="D">
				<a class="O" href="/admin:inside:addMIME">Agregar MIME</a>
				<div class="L"></div>
			</div>
			<div id="H" class="D">
				<a class="O" href="/admin:inside:addHeader">Agregar cabecera</a>
				<div class="L"></div>
			</div>
			<div id="W" class="D">
				<a class="O" href="/admin:inside:addRewrite">Agregar reescritura</a>
				<div class="L"></div>
			</div>
			<div id="J" class="D">
				<a class="O" href="/admin:inside:addPreprocessor">Agregar preprocesador</a>
				<div class="L"></div>
			</div>
			<div id="I" class="D">
				<a class="O" href="/admin:inside:addIndex">Agregar índice</a>
				<div class="L"></div>
			</div>
		</section>
	</main>
</body>
</html>`,
		},
	}
)
