(window.webpackJsonp=window.webpackJsonp||[]).push([[35,14,30],{290:function(t,e,o){var content=o(310);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("7c58e773",content,!0,{sourceMap:!1})},309:function(t,e,o){"use strict";o(290)},310:function(t,e,o){var n=o(27)((function(i){return i[1]}));n.push([t.i,".popup[data-v-4b387260]{top:1rem;left:50%;transform:translateX(-50%);z-index:10}.correct[data-v-4b387260]{background:#0aa000}.wrong[data-v-4b387260]{background:#d90e00}",""]),t.exports=n},317:function(t,e,o){"use strict";o.r(e);var n={props:{type:{type:String,required:!0}}},r=(o(309),o(11)),component=Object(r.a)(n,(function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",{class:[t.type,"popup","fixed","w-32","rounded","p-2"]},[o("h3",{staticClass:"text-center text-white",staticStyle:{margin:"0"}},[t._t("default")],2)])}),[],!1,null,"4b387260",null);e.default=component.exports},365:function(t,e,o){var content=o(446);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("338ffaa2",content,!0,{sourceMap:!1})},374:function(t,e,o){"use strict";var n=o(459),r=o.n(n);o(383),o(460),o(461),o(462),o(463),o(464),o(358);r.a.languages.vue=r.a.languages.markup,e.a=r.a},383:function(t,e,o){var content=o(384);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("a2210fe8",content,!0,{sourceMap:!1})},384:function(t,e,o){var n=o(27)((function(i){return i[1]}));n.push([t.i,'code[class*=language-],pre[class*=language-]{color:#fff;background:none;text-shadow:0 1px rgba(0,0,0,.3);font-family:"Fira Code",monospace;font-size:.95em;text-align:left;white-space:pre;word-spacing:normal;word-break:normal;word-wrap:normal;line-height:1.5;-moz-tab-size:4;-o-tab-size:4;tab-size:4;-webkit-hyphens:none;-ms-hyphens:none;hyphens:none}pre[class*=language-]{padding:1em;margin:.5em 0;overflow:auto;border-radius:.3em}:not(pre)>code[class*=language-],pre[class*=language-]{background:#2f4858}:not(pre)>code[class*=language-]{padding:.1em;border-radius:.3em;white-space:normal}.token.cdata,.token.comment,.token.doctype,.token.prolog{color:#6272a4}.token.punctuation{color:#fff}.namespace{opacity:.7}.token.constant,.token.deleted,.token.property,.token.symbol,.token.tag{color:#ff79c6}.token.boolean,.token.number{color:#bd93f9}.token.attr-name,.token.builtin,.token.char,.token.inserted,.token.selector,.token.string{color:#50fa7b}.language-css .token.string,.style .token.string,.token.entity,.token.operator,.token.url,.token.variable{color:#fff}.token.atrule,.token.attr-value,.token.class-name,.token.function{color:#f1fa8c}.token.keyword{color:#8be9fd}.token.important,.token.regex{color:#ffb86c}.token.bold,.token.important{font-weight:700}.token.italic{font-style:italic}.token.entity{cursor:help}.language-css .token.string,.style .token.string,.token.entity,.token.operator,.token.url{color:unset;background:unset}',""]),t.exports=n},419:function(t,e,o){var content=o(523);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("c167787c",content,!0,{sourceMap:!1})},420:function(t,e,o){var content=o(525);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("0db6b53b",content,!0,{sourceMap:!1})},424:function(t,e,o){"use strict";o.r(e);o(182),o(56);var n=o(374),r={name:"CodeBlock",components:{},props:{lang:{type:String,default:"text"}},mounted:function(){var t=this;this.$refs.code.firstChild.innerHTML=this.$refs.code.firstChild.innerHTML.trim(),setTimeout((function(){t.$refs.code.classList.add("language-"+t.lang),n.a.highlightAll()}),500)}},l=(o(445),o(11)),component=Object(l.a)(r,(function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",{staticClass:"codeblock-comp"},[o("pre",{ref:"code",staticClass:"codeblock"},[o("code",[t._t("default")],2)])])}),[],!1,null,"c26f8654",null);e.default=component.exports},445:function(t,e,o){"use strict";o(365)},446:function(t,e,o){var n=o(27)((function(i){return i[1]}));n.push([t.i,".codeblock-comp[data-v-c26f8654]{margin:2rem 0}",""]),t.exports=n},488:function(t,e,o){"use strict";o.r(e);o(56);var n=o(317),r=o(427),l=o(418),c=o.n(l),d={data:function(){return{isCorrect:!1,popUpComp:null,popUpType:null,popUpVal:null,prevTimeout:null,code:"int foo() {\n\n}",challCode:"",editorRO:null,buttonText:"SUBMIT",error:"",flag:""}},components:{PopUp:n.default,MonacoEditor:r.a},props:{answer:{type:String,required:!1},challId:String},mounted:function(){var t=this;this.editorRo=new ResizeObserver(this.resizeEditor).observe(this.$refs.editorCont),this.initTheme(),c.a.get("https://j0yl9v6lr1.execute-api.ap-southeast-1.amazonaws.com/Prod/pvpasm?chall=".concat(this.challId)).then((function(e){t.challCode=e.data})).catch((function(t){console.error(t)}));for(var i=0;i<3;++i)c.a.post("https://j0yl9v6lr1.execute-api.ap-southeast-1.amazonaws.com/Prod/pvpasm",{chall:this.challId,submission:this.code})},beforeDestroy:function(){this.editorRO&&this.editorRO.disconnect()},methods:{checkForm:function(t){var e=this;this.buttonText="...",c.a.post("https://j0yl9v6lr1.execute-api.ap-southeast-1.amazonaws.com/Prod/pvpasm/",{chall:this.challId,submission:this.code}).then((function(t){t.data.result?(t.data.flag&&(e.flag=t.data.flag),e.isCorrect=!0,e.popUpComp="PopUp",e.popUpType="correct",e.popUpVal="Correct!",window.clearTimeout(e.prevTimeout),e.prevTimeout=setTimeout(e.clearPopUp,2200)):(e.popUpComp="PopUp",e.popUpType="wrong",e.popUpVal="Wrong!",window.clearTimeout(e.prevTimeout),e.prevTimeout=setTimeout(e.clearPopUp,2200)),e.error=t.data.error,e.buttonText="SUBMIT"})).catch((function(t){console.error(t),console.error("Maybe try submitting again a few more times. It might just work."),e.popUpComp="PopUp",e.popUpType="wrong",e.popUpVal="Oops! Something went wrong. Please check the console and report to us.",window.clearTimeout(e.prevTimeout),e.prevTimeout=setTimeout(e.clearPopUp,2200),e.buttonText="SUBMIT"}))},clearPopUp:function(t){this.popUpComp=null,this.popUpType=null,this.popUpVal=null},resizeEditor:function(t){this.$refs.editor.getEditor().layout()},initTheme:function(){var t=this.$refs.editor.monaco;t.editor.defineTheme("omuTheme",{base:"vs-dark",inherit:!0,rules:[{background:"#2f4858"}],colors:{"editor.foreground":"#e5eff5","editor.background":"#2f4858","editorCursor.foreground":"#8B0000"}}),t.editor.setTheme("omuTheme")}}},f=(o(522),o(524),o(11)),component=Object(f.a)(d,(function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",{staticClass:"unare w-full overflow-hidden rounded-md my-8 mx-auto p-8 shadow-lg"},[o("h4",{staticClass:"text-lg uppercase font-medium text-gray-700"},[t._v("Quiz")]),t._v(" "),t._m(0),t._v(" "),t.flag?o("div",[o("p",{staticClass:"text-gray-700"},[t._v("Congrats! Flag: \n      "),o("code",{staticClass:"flag px-1 rounded"},[t._v(t._s(t.flag))])])]):t._e(),t._v(" "),o("div",{class:["unare-content",t.isCorrect?"correct":"wrong"]},[o("div",{staticClass:"line h-2 mt-4 mb-8 rounded"}),t._v(" "),o("div",{staticClass:"my-6 flex flex-row space-x-2.5"},[o("div",{staticClass:"code assembly rounded flex-grow"},[o("h4",{staticClass:"opacity-50 text-white ml-6 mt-3"},[t._v("Assembly (x86-64)")]),t._v(" "),o("CodeBlock",{key:t.challCode,staticClass:"codeblock px-2",attrs:{lang:"nasm"}},[t._v(t._s(t.challCode))])],1),t._v(" "),o("div",{staticClass:"code c rounded flex flex-col flex-grow"},[o("h4",{staticClass:"opacity-50 text-white ml-6 mt-3"},[t._v("C code")]),t._v(" "),o("div",{ref:"editorCont",staticClass:"editor-container h-full mt-5 mr-4 mb-3"},[o("MonacoEditor",{ref:"editor",staticClass:"editor h-full",attrs:{language:"c",options:{fontFamily:"Fira Code",fontWeight:"500",fontSize:"14rem"}},on:{editorDidMount:t.initTheme},model:{value:t.code,callback:function(e){t.code=e},expression:"code"}})],1)])]),t._v(" "),o("form",{on:{submit:function(e){return e.preventDefault(),t.checkForm(e)}}},[o("button",{staticClass:"block ml-auto"},[t._v(t._s(t.buttonText))])]),t._v(" "),o(t.popUpComp,{tag:"component",attrs:{type:t.popUpType}},[t._v(t._s(t.popUpVal))])],1),t._v(" "),t.error?o("p",{staticClass:"unare-error p-4 mt-4 mb-0 rounded whitespace-pre-line"},[t._v(t._s(t.error))]):t._e()])}),[function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("p",{staticClass:"mt-1 text-gray-700"},[t._v("\n    Write the equivalent "),o("strong",[t._v("C code")]),t._v(" for the following assembly\n    "),o("strong",[t._v("(x86-64)")]),t._v(" snippet.\n  ")])}],!1,null,"51f2f94b",null);e.default=component.exports;installComponents(component,{CodeBlock:o(424).default})},522:function(t,e,o){"use strict";o(419)},523:function(t,e,o){var n=o(27)((function(i){return i[1]}));n.push([t.i,'.wrong .line[data-v-51f2f94b]{max-width:20rem;background:#1ab2ff}.correct .line[data-v-51f2f94b]{max-width:100%;background:linear-gradient(90deg,#1ab2ff,#1aff7d)}button[data-v-51f2f94b]{background:#1ab2ff;box-shadow:0 1px 3px 0 hsla(0,0%,43.1%,.61);color:#fff;border-radius:.65rem;padding:.25rem .5rem}button[data-v-51f2f94b]:hover{background:#08c}strong[data-v-51f2f94b]{font-weight:400}.code[data-v-51f2f94b]{background:#2f4858;min-height:100px}.codeblock[data-v-51f2f94b]{margin-top:0!important}.assembly[data-v-51f2f94b]{min-width:400px}.c[data-v-51f2f94b]{min-width:450px}.edit-container[data-v-51f2f94b]{width:100%}.unare-error[data-v-51f2f94b]{font-family:"Fira Code",monospace;font-weight:500;font-size:.95em;background:#ff9797;margin-bottom:0!important}',""]),t.exports=n},524:function(t,e,o){"use strict";o(420)},525:function(t,e,o){var n=o(27)((function(i){return i[1]}));n.push([t.i,'.suggest-widget{display:none!important}.flag{font-family:"Fira Code",monospace;font-size:.875em;font-weight:500;background:#f0f0f0}',""]),t.exports=n},699:function(t,e){(function(e){t.exports=e}).call(this,{})}}]);