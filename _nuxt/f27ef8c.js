(window.webpackJsonp=window.webpackJsonp||[]).push([[22],{396:function(t,r,e){"use strict";var n=e(2),o=e(418).start;n({target:"String",proto:!0,forced:e(419)},{padStart:function(t){return o(this,t,arguments.length>1?arguments[1]:void 0)}})},418:function(t,r,e){var n=e(14),o=e(183),c=e(17),l=Math.ceil,f=function(t){return function(r,e,f){var d,v,x=String(c(r)),w=x.length,h=void 0===f?" ":String(f),m=n(e);return m<=w||""==h?x:(d=m-w,(v=o.call(h,l(d/h.length))).length>d&&(v=v.slice(0,d)),t?x+v:v+x)}};t.exports={start:f(!1),end:f(!0)}},419:function(t,r,e){var n=e(72);t.exports=/Version\/10(?:\.\d+){1,2}(?: [\w./]+)?(?: Mobile\/\w+)? Safari\//.test(n)},488:function(t,r,e){var content=e(644);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,e(28).default)("121fb786",content,!0,{sourceMap:!1})},643:function(t,r,e){"use strict";e(488)},644:function(t,r,e){var n=e(27)((function(i){return i[1]}));n.push([t.i,"li[data-v-50609598]{margin-bottom:.15rem}",""]),t.exports=n},779:function(t,r,e){"use strict";e.r(r);e(396),e(11),e(92),e(43);var n={name:"RegisterView",data:function(){return{registers:null}},created:function(){this.registers={rax:3735928559,rbx:3735928559,rcx:3735928559,rdx:3735928559,rsi:3735928559,rdi:3735928559,rip:3735928559,rsp:3735928559,rbp:3735928559,r8:3735928559,r9:3735928559,r10:3735928559,r11:3735928559,r12:3735928559,r13:3735928559,r14:3735928559,r15:3735928559}},props:{},methods:{formatHex:function(t){var s=t.toString(16).padStart(16,"0");return s.slice(0,8)+"`"+s.slice(8)}}},o=(e(643),e(13)),component=Object(o.a)(n,(function(){var t=this,r=t.$createElement,e=t._self._c||r;return e("div",{staticClass:"register-view m-1"},[e("ul",{staticClass:"flex flex-row flex-wrap justify-start"},t._l(Object.keys(t.registers),(function(r){return e("li",{key:r,staticClass:"mx-2"},[e("span",{staticClass:"text-gray-600"},[t._v(t._s((r+":").padEnd(4," ")))]),t._v("\n      "+t._s(t.formatHex(t.registers[r]))+"\n    ")])})),0)])}),[],!1,null,"50609598",null);r.default=component.exports}}]);