(window.webpackJsonp=window.webpackJsonp||[]).push([[37,21,22,23],{1229:function(t,e,n){"use strict";n.r(e);var r=n(759),o=n(760),f=n(761),l={components:{Window:r.default,MemoryView:o.default,RegisterView:f.default}},c=(n(771),n(13)),component=Object(c.a)(l,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"omulator w-full shadow-inner"},[n("div",{staticClass:"omulator-inner flex flex-row items-stretch"},[n("div",{staticClass:"left-half w-1/2 py-8 flex flex-col"},[n("Window",{attrs:{title:"Assembly (x86-64)"}},[n("div",{staticClass:"code-block py-4 px-2 rounded-lg"},[n("pre",{staticClass:"text-white"},[t._v("  ; main\n  1234 |     push    rbp\n  1235 |     mov     rbp, rsp\n  1236 |     mov     BYTE PTR [rbp-32], 97\n  1237 |     mov     BYTE PTR [rbp-64], 98\n  1238 |     mov     eax, 23\n  1239 |     pop     rbp\n  123a |     ret\n  ...\n  ; win\n  1337 |     push    rbp\n  1338 |     mov     rbp, rsp\n                  ")])])]),t._v(" "),n("Window",{attrs:{title:"Registers"}},[n("RegisterView")],1)],1),t._v(" "),n("div",{staticClass:"right-half w-1/2 py-8 flex flex-col justify-evenly"},[n("Window",{attrs:{title:"Stack"}},[n("MemoryView")],1),t._v(" "),n("Window",{attrs:{title:"Memory"}},[n("MemoryView")],1)],1)])])}),[],!1,null,null,null);e.default=component.exports},355:function(t,e,n){"use strict";var r=n(4),o=n(9),f=n(379),l=n(24),c=n(125),d=n(5),h=n(95),v=n(45),w=n(14),y=n(423),x=n(448),m=n(124),_=n(93),C=n(69).f,M=n(15).f,k=n(364),B=n(50),V=n(35),A=V.get,I=V.set,L="ArrayBuffer",O="DataView",S="Wrong index",U=r.ArrayBuffer,E=U,W=r.DataView,j=W&&W.prototype,D=Object.prototype,R=r.RangeError,F=x.pack,H=x.unpack,N=function(t){return[255&t]},$=function(t){return[255&t,t>>8&255]},T=function(t){return[255&t,t>>8&255,t>>16&255,t>>24&255]},z=function(t){return t[3]<<24|t[2]<<16|t[1]<<8|t[0]},J=function(t){return F(t,23,4)},P=function(t){return F(t,52,8)},Y=function(t,e){M(t.prototype,e,{get:function(){return A(this)[e]}})},G=function(view,t,e,n){var r=y(e),o=A(view);if(r+t>o.byteLength)throw R(S);var f=A(o.buffer).bytes,l=r+o.byteOffset,c=f.slice(l,l+t);return n?c:c.reverse()},K=function(view,t,e,n,r,o){var f=y(e),l=A(view);if(f+t>l.byteLength)throw R(S);for(var c=A(l.buffer).bytes,d=f+l.byteOffset,h=n(+r),i=0;i<t;i++)c[d+i]=h[o?i:t-i-1]};if(f){if(!d((function(){U(1)}))||!d((function(){new U(-1)}))||d((function(){return new U,new U(1.5),new U(NaN),U.name!=L}))){for(var Q,X=(E=function(t){return h(this,E),new U(y(t))}).prototype=U.prototype,Z=C(U),tt=0;Z.length>tt;)(Q=Z[tt++])in E||l(E,Q,U[Q]);X.constructor=E}_&&m(j)!==D&&_(j,D);var et=new W(new E(2)),nt=j.setInt8;et.setInt8(0,2147483648),et.setInt8(1,2147483649),!et.getInt8(0)&&et.getInt8(1)||c(j,{setInt8:function(t,e){nt.call(this,t,e<<24>>24)},setUint8:function(t,e){nt.call(this,t,e<<24>>24)}},{unsafe:!0})}else E=function(t){h(this,E,L);var e=y(t);I(this,{bytes:k.call(new Array(e),0),byteLength:e}),o||(this.byteLength=e)},W=function(t,e,n){h(this,W,O),h(t,E,O);var r=A(t).byteLength,f=v(e);if(f<0||f>r)throw R("Wrong offset");if(f+(n=void 0===n?r-f:w(n))>r)throw R("Wrong length");I(this,{buffer:t,byteLength:n,byteOffset:f}),o||(this.buffer=t,this.byteLength=n,this.byteOffset=f)},o&&(Y(E,"byteLength"),Y(W,"buffer"),Y(W,"byteLength"),Y(W,"byteOffset")),c(W.prototype,{getInt8:function(t){return G(this,1,t)[0]<<24>>24},getUint8:function(t){return G(this,1,t)[0]},getInt16:function(t){var e=G(this,2,t,arguments.length>1?arguments[1]:void 0);return(e[1]<<8|e[0])<<16>>16},getUint16:function(t){var e=G(this,2,t,arguments.length>1?arguments[1]:void 0);return e[1]<<8|e[0]},getInt32:function(t){return z(G(this,4,t,arguments.length>1?arguments[1]:void 0))},getUint32:function(t){return z(G(this,4,t,arguments.length>1?arguments[1]:void 0))>>>0},getFloat32:function(t){return H(G(this,4,t,arguments.length>1?arguments[1]:void 0),23)},getFloat64:function(t){return H(G(this,8,t,arguments.length>1?arguments[1]:void 0),52)},setInt8:function(t,e){K(this,1,t,N,e)},setUint8:function(t,e){K(this,1,t,N,e)},setInt16:function(t,e){K(this,2,t,$,e,arguments.length>2?arguments[2]:void 0)},setUint16:function(t,e){K(this,2,t,$,e,arguments.length>2?arguments[2]:void 0)},setInt32:function(t,e){K(this,4,t,T,e,arguments.length>2?arguments[2]:void 0)},setUint32:function(t,e){K(this,4,t,T,e,arguments.length>2?arguments[2]:void 0)},setFloat32:function(t,e){K(this,4,t,J,e,arguments.length>2?arguments[2]:void 0)},setFloat64:function(t,e){K(this,8,t,P,e,arguments.length>2?arguments[2]:void 0)}});B(E,L),B(W,O),t.exports={ArrayBuffer:E,DataView:W}},364:function(t,e,n){"use strict";var r=n(22),o=n(90),f=n(14);t.exports=function(t){for(var e=r(this),n=f(e.length),l=arguments.length,c=o(l>1?arguments[1]:void 0,n),d=l>2?arguments[2]:void 0,h=void 0===d?n:o(d,n);h>c;)e[c++]=t;return e}},379:function(t,e){t.exports="undefined"!=typeof ArrayBuffer&&"undefined"!=typeof DataView},380:function(t,e,n){"use strict";var r=n(2),o=n(399).start;r({target:"String",proto:!0,forced:n(400)},{padStart:function(t){return o(this,t,arguments.length>1?arguments[1]:void 0)}})},399:function(t,e,n){var r=n(14),o=n(183),f=n(17),l=Math.ceil,c=function(t){return function(e,n,c){var d,h,v=String(f(e)),w=v.length,y=void 0===c?" ":String(c),x=r(n);return x<=w||""==y?v:(d=x-w,(h=o.call(y,l(d/y.length))).length>d&&(h=h.slice(0,d)),t?v+h:h+v)}};t.exports={start:c(!1),end:c(!0)}},400:function(t,e,n){var r=n(72);t.exports=/Version\/10(?:\.\d+){1,2}(?: [\w./]+)?(?: Mobile\/\w+)? Safari\//.test(r)},423:function(t,e,n){var r=n(45),o=n(14);t.exports=function(t){if(void 0===t)return 0;var e=r(t),n=o(e);if(e!==n)throw RangeError("Wrong length or index");return n}},447:function(t,e,n){var content=n(552);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,n(28).default)("08f01b12",content,!0,{sourceMap:!1})},448:function(t,e){var n=Math.abs,r=Math.pow,o=Math.floor,f=Math.log,l=Math.LN2;t.exports={pack:function(t,e,c){var d,h,v,w=new Array(c),y=8*c-e-1,x=(1<<y)-1,m=x>>1,rt=23===e?r(2,-24)-r(2,-77):0,_=t<0||0===t&&1/t<0?1:0,C=0;for((t=n(t))!=t||t===1/0?(h=t!=t?1:0,d=x):(d=o(f(t)/l),t*(v=r(2,-d))<1&&(d--,v*=2),(t+=d+m>=1?rt/v:rt*r(2,1-m))*v>=2&&(d++,v/=2),d+m>=x?(h=0,d=x):d+m>=1?(h=(t*v-1)*r(2,e),d+=m):(h=t*r(2,m-1)*r(2,e),d=0));e>=8;w[C++]=255&h,h/=256,e-=8);for(d=d<<e|h,y+=e;y>0;w[C++]=255&d,d/=256,y-=8);return w[--C]|=128*_,w},unpack:function(t,e){var n,o=t.length,f=8*o-e-1,l=(1<<f)-1,c=l>>1,d=f-7,h=o-1,v=t[h--],w=127&v;for(v>>=7;d>0;w=256*w+t[h],h--,d-=8);for(n=w&(1<<-d)-1,w>>=-d,d+=e;d>0;n=256*n+t[h],h--,d-=8);if(0===w)w=1-c;else{if(w===l)return n?NaN:v?-1/0:1/0;n+=r(2,e),w-=c}return(v?-1:1)*n*r(2,w-e)}}},449:function(t,e,n){"use strict";var r=n(2),o=n(5),f=n(355),l=n(7),c=n(90),d=n(14),h=n(91),v=f.ArrayBuffer,w=f.DataView,y=v.prototype.slice;r({target:"ArrayBuffer",proto:!0,unsafe:!0,forced:o((function(){return!new v(2).slice(1,void 0).byteLength}))},{slice:function(t,e){if(void 0!==y&&void 0===e)return y.call(l(this),t);for(var n=l(this).byteLength,r=c(t,n),o=c(void 0===e?n:e,n),f=new(h(this,v))(d(o-r)),x=new w(this),m=new w(f),_=0;r<o;)m.setUint8(_++,x.getUint8(r++));return f}})},450:function(t,e,n){var content=n(556);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,n(28).default)("33fff32d",content,!0,{sourceMap:!1})},451:function(t,e,n){var content=n(558);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,n(28).default)("121fb786",content,!0,{sourceMap:!1})},551:function(t,e,n){"use strict";n(447)},552:function(t,e,n){var r=n(27)((function(i){return i[1]}));r.push([t.i,".window{font-size:.75rem;font-weight:500}@media only screen and (min-width:1280px){.window{font-size:1rem}}.tab{-webkit-clip-path:inset(-10px -10px 0 -10px);clip-path:inset(-10px -10px 0 -10px)}.panel{min-width:28rem;max-width:48rem}",""]),t.exports=r},553:function(t,e,n){"use strict";var r=n(2),o=n(4),f=n(355),l=n(126),c="ArrayBuffer",d=f.ArrayBuffer;r({global:!0,forced:o.ArrayBuffer!==d},{ArrayBuffer:d}),l(c)},554:function(t,e,n){var r=n(2),o=n(355);r({global:!0,forced:!n(379)},{DataView:o.DataView})},555:function(t,e,n){"use strict";n(450)},556:function(t,e,n){var r=n(27)((function(i){return i[1]}));r.push([t.i,"td[data-v-27f6577e]{line-height:1.15em;padding-right:2.3rem}td[data-v-27f6577e]:last-child{padding-right:0}",""]),t.exports=r},557:function(t,e,n){"use strict";n(451)},558:function(t,e,n){var r=n(27)((function(i){return i[1]}));r.push([t.i,"li[data-v-50609598]{margin-bottom:.15rem}",""]),t.exports=r},667:function(t,e,n){var content=n(772);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,n(28).default)("cea49e70",content,!0,{sourceMap:!1})},759:function(t,e,n){"use strict";n.r(e);var r={data:function(){return{}},props:{title:{type:String,required:!0}}},o=(n(551),n(13)),component=Object(o.a)(r,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"window my-4 mx-8"},[n("div",{staticClass:"tab inline-block bg-white py-1 px-3 shadow-md rounded-t-lg"},[n("h3",{staticClass:"inline"},[t._v(t._s(t.title))])]),t._v(" "),n("div",{staticClass:"panel bg-white p-4 shadow-md"},[t._t("default")],2)])}),[],!1,null,null,null);e.default=component.exports},760:function(t,e,n){"use strict";n.r(e);n(553),n(449),n(11),n(554),n(380),n(92),n(43);var r={data:function(){return{buffer:null,dv:null,test:null}},created:function(){this.buffer=new ArrayBuffer(320),this.dv=new DataView(this.buffer),this.test=123},props:{},methods:{formatHex:function(t){var s=t.toString(16).padStart(16,"0");return s.slice(0,8)+"`"+s.slice(8)}}},o=(n(555),n(13)),component=Object(o.a)(r,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"memory-view mx-5 mt-3 mb-4"},[n("input",{staticClass:"rounded w-36 px-2 text-gray-600 border border-gray-600",attrs:{type:"text",placeholder:"$rax+0x100"}}),t._v(" "),n("table",{staticClass:"ml-2 mt-2"},t._l(10,(function(e){return n("tr",{key:e},[n("td",{staticClass:"address text-gray-600"},[t._v(t._s(t.formatHex(16*e)+": "))]),t._v(" "),n("td",[t._v(t._s(t.formatHex(t.dv.getBigUint64(16*e))))]),t._v(" "),n("td",[t._v(t._s(t.formatHex(t.dv.getBigUint64(16*e+8))))])])})),0)])}),[],!1,null,"27f6577e",null);e.default=component.exports},761:function(t,e,n){"use strict";n.r(e);n(380),n(11),n(92),n(43);var r={name:"RegisterView",data:function(){return{registers:null}},created:function(){this.registers={rax:3735928559,rbx:3735928559,rcx:3735928559,rdx:3735928559,rsi:3735928559,rdi:3735928559,rip:3735928559,rsp:3735928559,rbp:3735928559,r8:3735928559,r9:3735928559,r10:3735928559,r11:3735928559,r12:3735928559,r13:3735928559,r14:3735928559,r15:3735928559}},props:{},methods:{formatHex:function(t){var s=t.toString(16).padStart(16,"0");return s.slice(0,8)+"`"+s.slice(8)}}},o=(n(557),n(13)),component=Object(o.a)(r,(function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"register-view m-1"},[n("ul",{staticClass:"flex flex-row flex-wrap justify-start"},t._l(Object.keys(t.registers),(function(e){return n("li",{key:e,staticClass:"mx-2"},[n("span",{staticClass:"text-gray-600"},[t._v(t._s((e+":").padEnd(4," ")))]),t._v("\n      "+t._s(t.formatHex(t.registers[e]))+"\n    ")])})),0)])}),[],!1,null,"50609598",null);e.default=component.exports},771:function(t,e,n){"use strict";n(667)},772:function(t,e,n){var r=n(27)((function(i){return i[1]}));r.push([t.i,'.omulator{background:#e4ebf1;font-family:"Fira Code",monospace}.omulator-inner{max-width:1920px;margin:0 auto}pre{font-family:"Fira Code",monospace}.code-block{background:#2f4858}',""]),t.exports=r}}]);