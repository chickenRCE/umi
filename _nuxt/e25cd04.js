(window.webpackJsonp=window.webpackJsonp||[]).push([[30,26],{1238:function(t,e,o){"use strict";o.r(e);o(58);var r={data:function(){return{isCorrect:!1,popUpComp:null,popUpType:null,popUpVal:null,prevTimeout:null}},components:{PopUp:o(330).default},props:{answer:{type:String,required:!0}},methods:{checkForm:function(t){this.$refs.user_ans.value.localeCompare(this.answer)?(this.popUpComp="PopUp",this.popUpType="wrong",this.popUpVal="Wrong!",window.clearTimeout(this.prevTimeout),this.prevTimeout=setTimeout(this.clearPopUp,2200)):(this.isCorrect=!0,this.popUpComp="PopUp",this.popUpType="correct",this.popUpVal="Correct!",window.clearTimeout(this.prevTimeout),this.prevTimeout=setTimeout(this.clearPopUp,2200))},clearPopUp:function(t){this.popUpComp=null,this.popUpType=null,this.popUpVal=null}}},n=(o(811),o(13)),component=Object(n.a)(r,(function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",{class:["text-quiz",t.isCorrect?"correct":"wrong"]},[o("div",{staticClass:"line h-2 mt-4 mb-8 rounded"}),t._v(" "),o("h4",{staticClass:"quiz-question text-xl mb-6 font-medium"},[t._t("default")],2),t._v(" "),o("form",{on:{submit:function(e){return e.preventDefault(),t.checkForm(e)}}},[o("input",{ref:"user_ans",staticClass:"border w-full mb-8 rounded-lg p-1 px-2",attrs:{disabled:t.isCorrect,type:"text",placeholder:"Answer"}}),t._v(" "),o("button",{staticClass:"block ml-auto"},[t._v("SUBMIT")])]),t._v(" "),o(t.popUpComp,{tag:"component",attrs:{type:t.popUpType}},[t._v(t._s(t.popUpVal))])],1)}),[],!1,null,"2baa711a",null);e.default=component.exports},294:function(t,e,o){var content=o(322);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("7c58e773",content,!0,{sourceMap:!1})},321:function(t,e,o){"use strict";o(294)},322:function(t,e,o){var r=o(27)((function(i){return i[1]}));r.push([t.i,".popup[data-v-4b387260]{top:1rem;left:50%;transform:translateX(-50%);z-index:10}.correct[data-v-4b387260]{background:#0aa000}.wrong[data-v-4b387260]{background:#d90e00}",""]),t.exports=r},330:function(t,e,o){"use strict";o.r(e);var r={props:{type:{type:String,required:!0}}},n=(o(321),o(13)),component=Object(n.a)(r,(function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("div",{class:[t.type,"popup","fixed","w-32","rounded","p-2"]},[o("h3",{staticClass:"text-center text-white",staticStyle:{margin:"0"}},[t._t("default")],2)])}),[],!1,null,"4b387260",null);e.default=component.exports},683:function(t,e,o){var content=o(812);content.__esModule&&(content=content.default),"string"==typeof content&&(content=[[t.i,content,""]]),content.locals&&(t.exports=content.locals);(0,o(28).default)("3c1936fb",content,!0,{sourceMap:!1})},811:function(t,e,o){"use strict";o(683)},812:function(t,e,o){var r=o(27)((function(i){return i[1]}));r.push([t.i,".wrong .line[data-v-2baa711a]{max-width:20rem;background:#1ab2ff}.correct .line[data-v-2baa711a]{max-width:100%;background:linear-gradient(90deg,#1ab2ff,#1aff7d)}",""]),t.exports=r}}]);