(window.webpackJsonp=window.webpackJsonp||[]).push([[33,13,20,26,31],{1096:function(t,e,o){"use strict";o(760)},1097:function(t,e,o){var n=o(27)((function(i){return i[1]}));n.push([t.i,'.link[data-v-2bf0f718]{text-decoration:none;border-bottom:2px solid #ecb5c7}.link[data-v-2bf0f718]:hover{color:inherit;-webkit-transition:.4s ease;-moz-transition:.4s ease;border-bottom:2px solid #c20447}blockquote[data-v-2bf0f718]{background:#f0f0f0}code[data-v-2bf0f718]{font-family:"Fira Code",monospace;font-size:.875em;font-weight:500}',""]),t.exports=n},1234:function(t,e,o){"use strict";o.r(e);o(561);var n=o(654),r={name:"Index",data:function(){return{showcase:null}},components:{ModuleWidget:o(550).default,Unare:n.default}},l=(o(1096),o(13)),component=Object(l.a)(r,(function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",[o("main",{staticClass:"w-full mt-4"},[t._m(0),t._v(" "),o("div",{staticClass:"mt-8 m-auto max-w-5xl"},[o("section",{staticClass:"p-8"},[o("NuxtLink",{attrs:{to:"#overview"}},[o("h2",{staticClass:"text-4xl pb-4",attrs:{id:"overview"}},[t._v("Overview")])]),t._v(" "),t._m(1),t._v(" "),t._m(2),t._v(" "),o("p",{staticClass:"text-lg"},[t._v("If you are unsure of how to start with solving these challenges, you can consider learning more about the core concepts from our\n          "),o("span",{staticClass:"link"},[o("NuxtLink",{attrs:{to:"/"}},[t._v("omu")])],1),t._v(" platform.\n        ")]),t._v(" "),o("br"),t._v(" "),o("p",{staticClass:"text-lg"},[t._v("Specifically, the "),o("span",{staticClass:"link"},[o("NuxtLink",{attrs:{to:"/lessons/asm-x86-64"}},[t._v("ASM (x86-64)")])],1),t._v(" module would be most relevant.")])],1),t._v(" "),o("section",{staticClass:"p-8"},[o("NuxtLink",{attrs:{to:"#introduction"}},[o("h2",{staticClass:"text-4xl pb-4",attrs:{id:"introduction"}},[t._v("Introduction")])]),t._v(" "),o("p",{staticClass:"text-lg"},[t._v("Each mini challenge will comprise of a snippet of assembly code (x86-64) from a C function.")]),t._v(" "),o("p",{staticClass:"text-lg"},[t._v("In the panel on the left, you are expected to write the corresponding C code to create a function that would match behaviour to the assembly snippet provided.")]),t._v(" "),o("br"),t._v(" "),o("h3",{staticClass:"text-2xl pb-4"},[t._v("Tip #1: Register convention")]),t._v(" "),t._m(3),t._v(" "),o("p",{staticClass:"text-lg"},[t._v("The most important piece of information you need from the link is this:")]),t._v(" "),t._m(4),t._v(" "),t._m(5)],1),t._v(" "),o("section",{staticClass:"p-8"},[o("NuxtLink",{attrs:{to:"#chal-1"}},[o("h2",{staticClass:"text-4xl pb-4",attrs:{id:"chal-1"}},[t._v("Challenge #1")])]),t._v(" "),o("p",{staticClass:"text-lg"},[t._v("We'll start easy with this one, try to read each instruction and understand what's going on.")]),t._v(" "),o("Unare",{attrs:{"chall-id":"acs-1"}})],1),t._v(" "),o("section",{staticClass:"p-8"},[o("NuxtLink",{attrs:{to:"#chal-2"}},[o("h2",{staticClass:"text-4xl pb-4",attrs:{id:"chal-2"}},[t._v("Challenge #2")])]),t._v(" "),o("p",{staticClass:"text-lg"},[t._v("This should be a code structure that you use very often when programming!")]),t._v(" "),o("Unare",{attrs:{"chall-id":"acs-2"}})],1),t._v(" "),o("section",{staticClass:"p-8"},[o("NuxtLink",{attrs:{to:"#chal-3"}},[o("h2",{staticClass:"text-4xl pb-4",attrs:{id:"chal-3"}},[t._v("Challenge #3")])]),t._v(" "),o("p",{staticClass:"text-lg"},[t._v("The final challenge, you're almost there!")]),t._v(" "),o("Unare",{attrs:{"chall-id":"acs-3"}})],1)])])])}),[function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",{staticClass:"max-w-5xl mx-auto text-center"},[o("img",{staticClass:"mx-auto",staticStyle:{height:"300px"},attrs:{src:"/img/acs-ctf-logo.png",alt:"ACS CTF Logo"}}),t._v(" "),o("h1",{staticClass:"text-6xl"},[t._v("\n        Hack@AC omu challenge\n      ")])])},function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("p",{staticClass:"text-lg"},[t._v("We have prepared a series of small "),o("strong",[t._v("Reverse Engineering")]),t._v(" challenges to test your skills!")])},function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("p",{staticClass:"text-lg"},[t._v("Solve all "),o("strong",[t._v("3")]),t._v(" mini challenges to get the flag for this special omu challenge.")])},function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("p",{staticClass:"text-lg"},[t._v("The register convention used by our code snippets follow the "),o("span",{staticClass:"link"},[o("a",{attrs:{href:"https://wiki.osdev.org/System_V_ABI"}},[t._v("System V ABI")])]),t._v(", which is the default with GCC on Linux.")])},function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("blockquote",{staticClass:"my-6 p-2 border-l-2 border-black"},[t._v("\n          This is a 64-bit platform. The stack grows downwards. Parameters to functions are passed in the registers rdi, rsi, rdx, rcx, r8, r9, and further values are passed on the stack in reverse order. \n          "),o("br"),t._v("\n          ...\n          "),o("br"),t._v("\n          The return value is stored in the rax register\n        ")])},function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("p",{staticClass:"text-lg"},[t._v("Make sure you place your return value in "),o("code",[t._v("rax")]),t._v("!")])}],!1,null,"2bf0f718",null);e.default=component.exports;installComponents(component,{Unare:o(654).default})},290:function(t,e,o){var content=o(311);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("7c58e773",content,!0,{sourceMap:!1})},310:function(t,e,o){"use strict";o(290)},311:function(t,e,o){var n=o(27)((function(i){return i[1]}));n.push([t.i,".popup[data-v-4b387260]{top:1rem;left:50%;transform:translateX(-50%);z-index:10}.correct[data-v-4b387260]{background:#0aa000}.wrong[data-v-4b387260]{background:#d90e00}",""]),t.exports=n},322:function(t,e,o){"use strict";o.r(e);var n={props:{type:{type:String,required:!0}}},r=(o(310),o(13)),component=Object(r.a)(n,(function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",{class:[t.type,"popup","fixed","w-32","rounded","p-2"]},[o("h3",{staticClass:"text-center text-white",staticStyle:{margin:"0"}},[t._t("default")],2)])}),[],!1,null,"4b387260",null);e.default=component.exports},393:function(t,e,o){var content=o(481);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("281fc637",content,!0,{sourceMap:!1})},394:function(t,e,o){var content=o(483);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("2562eca8",content,!0,{sourceMap:!1})},478:function(t,e,o){var content=o(634);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("c167787c",content,!0,{sourceMap:!1})},479:function(t,e,o){var content=o(636);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("0db6b53b",content,!0,{sourceMap:!1})},480:function(t,e,o){"use strict";o(393)},481:function(t,e,o){var n=o(27)((function(i){return i[1]}));n.push([t.i,".codeblock-comp[data-v-b5d7600a]{margin:2rem 0}",""]),t.exports=n},482:function(t,e,o){"use strict";o(394)},483:function(t,e,o){var n=o(27)((function(i){return i[1]}));n.push([t.i,"a[data-v-2a7f09d6]{text-decoration:none}a[data-v-2a7f09d6]:hover{color:currentcolor}",""]),t.exports=n},549:function(t,e,o){"use strict";o.r(e);o(181);var n={name:"CodeBlock",components:{},props:{lang:{type:String,default:"text"}},mounted:function(){Prism.highlightAll(),this.$refs.code.firstChild.innerHTML=this.$refs.code.firstChild.innerHTML.trim()}},r=(o(480),o(13)),component=Object(r.a)(n,(function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",{staticClass:"codeblock-comp"},[o("pre",{ref:"code",class:["codeblock","language-"+t.lang]},[o("code",[t._t("default")],2)])])}),[],!1,null,"b5d7600a",null);e.default=component.exports},550:function(t,e,o){"use strict";o.r(e);var n={name:"ModuleWidget",props:{full:{type:Boolean,default:!1}}},r=(o(482),o(13)),component=Object(r.a)(n,(function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("NuxtLink",{attrs:{to:"/lessons"}},[o("div",{class:["widget","mt-4",t.full?"w-full":"w-60",t.full?"":"h-52","py-8","px-10","widget","rounded-lg","flex","flex-col","justify-between","relative"]},[o("a",{staticClass:"w-full h-full absolute",attrs:{href:"/lessons"}}),t._v(" "),o("p",{class:[t.full?"text-2xl":"text-lg","font-semibold"]},[t._v("\n      Linux Basics\n      "),o("img",{staticClass:"inline float-right",style:{height:t.full?"6.25rem":"1.5rem",width:"auto"},attrs:{src:"https://ouch-cdn2.icons8.com/ytkpLqS0r3VpKy0eWvOYNgCHXeFp_6w24wUi4gOu-fQ/rs:fit:1926:912/czM6Ly9pY29uczgu/b3VjaC1wcm9kLmFz/c2V0cy9zdmcvODkw/LzdjMTdkYWU0LWFi/MDYtNDZhMy1hNTEy/LTllNzczOGViMzVm/ZS5zdmc.png",alt:"computer"}})]),t._v(" "),o("div",[o("div",{staticClass:"relative pt-1 my-4"},[o("div",{staticClass:"overflow-hidden h-2 text-xs flex rounded bg-green-200"})]),t._v(" "),o("div",{staticClass:"font-medium pt-2 pb-1"},[t._v("Difficulty: Easy")]),t._v(" "),o("div",{class:t.full?"text-lg":"text-sm"},[t._v("\n        Learn the basics of interacting with OSes in the Linux family.\n      ")])]),t._v(" "),t.full?t._e():o("h3",{staticClass:"invisible text-lg"},[t._v("Linux Basics")])])])}),[],!1,null,"2a7f09d6",null);e.default=component.exports},561:function(t,e,o){"use strict";var n=o(682),r=o.n(n);o(562),o(683),o(684),o(685),o(686),o(687),o(499);r.a.languages.vue=r.a.languages.markup,e.a=r.a},562:function(t,e,o){var content=o(563);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("a2210fe8",content,!0,{sourceMap:!1})},563:function(t,e,o){var n=o(27)((function(i){return i[1]}));n.push([t.i,'code[class*=language-],pre[class*=language-]{color:#fff;background:none;text-shadow:0 1px rgba(0,0,0,.3);font-family:"Fira Code",monospace;font-size:.95em;text-align:left;white-space:pre;word-spacing:normal;word-break:normal;word-wrap:normal;line-height:1.5;-moz-tab-size:4;-o-tab-size:4;tab-size:4;-webkit-hyphens:none;-ms-hyphens:none;hyphens:none}pre[class*=language-]{padding:1em;margin:.5em 0;overflow:auto;border-radius:.3em}:not(pre)>code[class*=language-],pre[class*=language-]{background:#2f4858}:not(pre)>code[class*=language-]{padding:.1em;border-radius:.3em;white-space:normal}.token.cdata,.token.comment,.token.doctype,.token.prolog{color:#6272a4}.token.punctuation{color:#fff}.namespace{opacity:.7}.token.constant,.token.deleted,.token.property,.token.symbol,.token.tag{color:#ff79c6}.token.boolean,.token.number{color:#bd93f9}.token.attr-name,.token.builtin,.token.char,.token.inserted,.token.selector,.token.string{color:#50fa7b}.language-css .token.string,.style .token.string,.token.entity,.token.operator,.token.url,.token.variable{color:#fff}.token.atrule,.token.attr-value,.token.class-name,.token.function{color:#f1fa8c}.token.keyword{color:#8be9fd}.token.important,.token.regex{color:#ffb86c}.token.bold,.token.important{font-weight:700}.token.italic{font-style:italic}.token.entity{cursor:help}.language-css .token.string,.style .token.string,.token.entity,.token.operator,.token.url{color:unset;background:unset}',""]),t.exports=n},626:function(t,e){(function(e){t.exports=e}).call(this,{})},633:function(t,e,o){"use strict";o(478)},634:function(t,e,o){var n=o(27)((function(i){return i[1]}));n.push([t.i,'.wrong .line[data-v-51f2f94b]{max-width:20rem;background:#1ab2ff}.correct .line[data-v-51f2f94b]{max-width:100%;background:linear-gradient(90deg,#1ab2ff,#1aff7d)}button[data-v-51f2f94b]{background:#1ab2ff;box-shadow:0 1px 3px 0 hsla(0,0%,43.1%,.61);color:#fff;border-radius:.65rem;padding:.25rem .5rem}button[data-v-51f2f94b]:hover{background:#08c}strong[data-v-51f2f94b]{font-weight:400}.code[data-v-51f2f94b]{background:#2f4858;min-height:100px}.codeblock[data-v-51f2f94b]{margin-top:0!important}.assembly[data-v-51f2f94b]{min-width:400px}.c[data-v-51f2f94b]{min-width:450px}.edit-container[data-v-51f2f94b]{width:100%}.unare-error[data-v-51f2f94b]{font-family:"Fira Code",monospace;font-weight:500;font-size:.95em;background:#ff9797;margin-bottom:0!important}',""]),t.exports=n},635:function(t,e,o){"use strict";o(479)},636:function(t,e,o){var n=o(27)((function(i){return i[1]}));n.push([t.i,'.suggest-widget{display:none!important}.flag{font-family:"Fira Code",monospace;font-size:.875em;font-weight:500;background:#f0f0f0}',""]),t.exports=n},654:function(t,e,o){"use strict";o.r(e);o(58);var n=o(322),r=o(564),l=o(542),c=o.n(l),d={data:function(){return{isCorrect:!1,popUpComp:null,popUpType:null,popUpVal:null,prevTimeout:null,code:"int foo() {\n\n}",challCode:"",editorRO:null,buttonText:"SUBMIT",error:"",flag:""}},components:{PopUp:n.default,MonacoEditor:r.a},props:{answer:{type:String,required:!1},challId:String},mounted:function(){var t=this;this.editorRo=new ResizeObserver(this.resizeEditor).observe(this.$refs.editorCont),this.initTheme(),c.a.get("https://j0yl9v6lr1.execute-api.ap-southeast-1.amazonaws.com/Prod/pvpasm?chall=".concat(this.challId)).then((function(e){t.challCode=e.data})).catch((function(t){console.error(t)}));for(var i=0;i<3;++i)c.a.post("https://j0yl9v6lr1.execute-api.ap-southeast-1.amazonaws.com/Prod/pvpasm",{chall:this.challId,submission:this.code})},beforeDestroy:function(){this.editorRO&&this.editorRO.disconnect()},methods:{checkForm:function(t){var e=this;this.buttonText="...",c.a.post("https://j0yl9v6lr1.execute-api.ap-southeast-1.amazonaws.com/Prod/pvpasm/",{chall:this.challId,submission:this.code}).then((function(t){t.data.result?(t.data.flag&&(e.flag=t.data.flag),e.isCorrect=!0,e.popUpComp="PopUp",e.popUpType="correct",e.popUpVal="Correct!",window.clearTimeout(e.prevTimeout),e.prevTimeout=setTimeout(e.clearPopUp,2200)):(e.popUpComp="PopUp",e.popUpType="wrong",e.popUpVal="Wrong!",window.clearTimeout(e.prevTimeout),e.prevTimeout=setTimeout(e.clearPopUp,2200)),e.error=t.data.error,e.buttonText="SUBMIT"})).catch((function(t){console.error(t),console.error("Maybe try submitting again a few more times. It might just work."),e.popUpComp="PopUp",e.popUpType="wrong",e.popUpVal="Oops! Something went wrong. Please check the console and report to us.",window.clearTimeout(e.prevTimeout),e.prevTimeout=setTimeout(e.clearPopUp,2200),e.buttonText="SUBMIT"}))},clearPopUp:function(t){this.popUpComp=null,this.popUpType=null,this.popUpVal=null},resizeEditor:function(t){this.$refs.editor.getEditor().layout()},initTheme:function(){var t=this.$refs.editor.monaco;t.editor.defineTheme("omuTheme",{base:"vs-dark",inherit:!0,rules:[{background:"#2f4858"}],colors:{"editor.foreground":"#e5eff5","editor.background":"#2f4858","editorCursor.foreground":"#8B0000"}}),t.editor.setTheme("omuTheme")}}},f=(o(633),o(635),o(13)),component=Object(f.a)(d,(function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",{staticClass:"unare w-full overflow-hidden rounded-md my-8 mx-auto p-8 shadow-lg"},[o("h4",{staticClass:"text-lg uppercase font-medium text-gray-700"},[t._v("Quiz")]),t._v(" "),t._m(0),t._v(" "),t.flag?o("div",[o("p",{staticClass:"text-gray-700"},[t._v("Congrats! Flag: \n      "),o("code",{staticClass:"flag px-1 rounded"},[t._v(t._s(t.flag))])])]):t._e(),t._v(" "),o("div",{class:["unare-content",t.isCorrect?"correct":"wrong"]},[o("div",{staticClass:"line h-2 mt-4 mb-8 rounded"}),t._v(" "),o("div",{staticClass:"my-6 flex flex-row space-x-2.5"},[o("div",{staticClass:"code assembly rounded flex-grow"},[o("h4",{staticClass:"opacity-50 text-white ml-6 mt-3"},[t._v("Assembly (x86-64)")]),t._v(" "),o("CodeBlock",{key:t.challCode,staticClass:"codeblock px-2",attrs:{lang:"nasm"}},[t._v(t._s(t.challCode))])],1),t._v(" "),o("div",{staticClass:"code c rounded flex flex-col flex-grow"},[o("h4",{staticClass:"opacity-50 text-white ml-6 mt-3"},[t._v("C code")]),t._v(" "),o("div",{ref:"editorCont",staticClass:"editor-container h-full mt-5 mr-4 mb-3"},[o("MonacoEditor",{ref:"editor",staticClass:"editor h-full",attrs:{language:"c",options:{fontFamily:"Fira Code",fontWeight:"500",fontSize:"14rem"}},on:{editorDidMount:t.initTheme},model:{value:t.code,callback:function(e){t.code=e},expression:"code"}})],1)])]),t._v(" "),o("form",{on:{submit:function(e){return e.preventDefault(),t.checkForm(e)}}},[o("button",{staticClass:"block ml-auto"},[t._v(t._s(t.buttonText))])]),t._v(" "),o(t.popUpComp,{tag:"component",attrs:{type:t.popUpType}},[t._v(t._s(t.popUpVal))])],1),t._v(" "),t.error?o("p",{staticClass:"unare-error p-4 mt-4 mb-0 rounded whitespace-pre-line"},[t._v(t._s(t.error))]):t._e()])}),[function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("p",{staticClass:"mt-1 text-gray-700"},[t._v("\n    Write the equivalent "),o("strong",[t._v("C code")]),t._v(" for the following assembly\n    "),o("strong",[t._v("(x86-64)")]),t._v(" snippet.\n  ")])}],!1,null,"51f2f94b",null);e.default=component.exports;installComponents(component,{CodeBlock:o(549).default})},760:function(t,e,o){var content=o(1097);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("55644efb",content,!0,{sourceMap:!1})}}]);