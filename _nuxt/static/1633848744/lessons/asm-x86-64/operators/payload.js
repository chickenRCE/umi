__NUXT_JSONP__("/lessons/asm-x86-64/operators", (function(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,_,$,aa,ab,ac,ad,ae,af,ag){return {data:[{content:{slug:"operators",layout:"lesson",module:D,title:"Operators",desc:"Perform operations on data",order:5,omulator:Q,toc:[{id:R,depth:w,text:S},{id:T,depth:w,text:U},{id:u,depth:n,text:u},{id:V,depth:n,text:W},{id:X,depth:n,text:Y},{id:Z,depth:w,text:_},{id:x,depth:n,text:x},{id:y,depth:n,text:y},{id:z,depth:n,text:z},{id:A,depth:n,text:A},{id:$,depth:w,text:aa}],body:{type:"root",children:[{type:b,tag:e,props:{},children:[{type:a,value:"Now we understand how to assign values to and between registers, but that wouldn't be very useful to do much.\nThat's where operators come in.\nIf you've never heard of the term operators from programming, it is just a fancy way to refer to actions that we can perform."}]},{type:a,value:c},{type:b,tag:E,props:{id:R},children:[{type:b,tag:f,props:{href:"#basic-operator-syntax",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:S}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"In x86-64 assembly, most operators "},{type:b,tag:L,props:{},children:[{type:a,value:"tend"}]},{type:a,value:" to follow a general structure.\nIt's helpful to learn this structure so you can learn to use operators you've never seen before, even without consulting the documentation too much."}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"In general, most operators are used in the following structure:"}]},{type:a,value:c},{type:b,tag:m,props:{className:[o]},children:[{type:b,tag:p,props:{className:[q,M]},children:[{type:b,tag:d,props:{},children:[{type:a,value:"operator src, dst\n"}]}]}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:b,tag:d,props:{},children:[{type:a,value:r}]},{type:a,value:s},{type:b,tag:d,props:{},children:[{type:a,value:v}]},{type:a,value:" are referred to as "},{type:b,tag:l,props:{},children:[{type:a,value:"operands"}]},{type:a,value:", meaning they are the objects being operated on.\nSo far, we've covered one type of operand, registers!\nAnother popular form of operands are memory addresses, but we will cover this in a future lesson."}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"If you're familiar with programming, the above instruction will then do something like so."}]},{type:a,value:c},{type:b,tag:m,props:{className:[o]},children:[{type:b,tag:p,props:{className:[q,F]},children:[{type:b,tag:d,props:{},children:[{type:a,value:"src = operator(src, dst);\n"}]}]}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"As we can see, the operator is applied to both operands, and the resultant value is stored back into the "},{type:b,tag:d,props:{},children:[{type:a,value:r}]},{type:a,value:" operand.\nLet's try this out with a real operator."}]},{type:a,value:c},{type:b,tag:E,props:{id:T},children:[{type:b,tag:f,props:{href:"#arithmetic-operators",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:U}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"As children the first operator we usually learn is addition.\nLet's do the same here."}]},{type:a,value:c},{type:b,tag:m,props:{className:[o]},children:[{type:b,tag:p,props:{className:[q,M]},children:[{type:b,tag:d,props:{},children:[{type:a,value:"add src, dst\n"}]}]}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:B},{type:b,tag:d,props:{},children:[{type:a,value:G}]},{type:a,value:" instruction is the operator that handles "},{type:b,tag:L,props:{},children:[{type:a,value:"addition"}]},{type:a,value:ab},{type:b,tag:d,props:{},children:[{type:a,value:"+"}]},{type:a,value:")!\nAs mentioned earlier, the above instruction will reassign "},{type:b,tag:d,props:{},children:[{type:a,value:r}]},{type:a,value:" with the value of "},{type:b,tag:d,props:{},children:[{type:a,value:"add(src, dst)"}]},{type:a,value:ab},{type:b,tag:d,props:{},children:[{type:a,value:"src + dst"}]},{type:a,value:").\nTry to predict the resultant value of "},{type:b,tag:d,props:{},children:[{type:a,value:N}]},{type:a,value:", before running the code to verify your answer."}]},{type:a,value:c},{type:b,tag:H,props:{"initial-code":"\nmov rax, 10\nmov rbx, 20\nadd rax, rbx\n"},children:[{type:a,value:I}]},{type:a,value:c},{type:b,tag:"info-box",props:{},children:[{type:a,value:"\nOn top of "},{type:b,tag:d,props:{},children:[{type:a,value:G}]},{type:a,value:", there are various other instructions for the other arithmetic operations.\nWe've listed the common ones below.\n"}]},{type:a,value:c},{type:b,tag:t,props:{id:u},children:[{type:b,tag:f,props:{href:"#sub",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:u}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:b,tag:d,props:{},children:[{type:a,value:u}]},{type:a,value:" is used for subtraction ("},{type:b,tag:d,props:{},children:[{type:a,value:"-"}]},{type:a,value:").\nIt's functionality is very similar to that of "},{type:b,tag:d,props:{},children:[{type:a,value:G}]},{type:a,value:"."}]},{type:a,value:c},{type:b,tag:H,props:{"initial-code":"\nmov rax, 100\nmov rbx, 30\nsub rax, rbx\n"},children:[{type:a,value:I}]},{type:a,value:c},{type:b,tag:t,props:{id:V},children:[{type:b,tag:f,props:{href:"#imulmul",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:W}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:b,tag:d,props:{},children:[{type:a,value:C}]},{type:a,value:" is used for "},{type:b,tag:L,props:{},children:[{type:a,value:"signed"}]},{type:a,value:" multiplication ("},{type:b,tag:d,props:{},children:[{type:a,value:ac}]},{type:a,value:")."}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"There are three forms that can be used for this instruction:"}]},{type:a,value:c},{type:b,tag:"ol",props:{},children:[{type:a,value:c},{type:b,tag:O,props:{},children:[{type:a,value:"one-operand form"}]},{type:a,value:c},{type:b,tag:O,props:{},children:[{type:a,value:"two-operand form"}]},{type:a,value:c},{type:b,tag:O,props:{},children:[{type:a,value:"three-operand form"}]},{type:a,value:c}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:b,tag:l,props:{},children:[{type:a,value:"two-operand"}]},{type:a,value:" form is similar to that of "},{type:b,tag:d,props:{},children:[{type:a,value:G}]},{type:a,value:s},{type:b,tag:d,props:{},children:[{type:a,value:u}]},{type:a,value:".\nInstructions using this form will be written as:"}]},{type:a,value:c},{type:b,tag:m,props:{className:[o]},children:[{type:b,tag:p,props:{className:[q,M]},children:[{type:b,tag:d,props:{},children:[{type:a,value:"imul src, dst\n"}]}]}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"Which results in"}]},{type:a,value:c},{type:b,tag:m,props:{className:[o]},children:[{type:b,tag:p,props:{className:[q,F]},children:[{type:b,tag:d,props:{},children:[{type:a,value:"src = src * dst\n"}]}]}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:b,tag:l,props:{},children:[{type:a,value:J}]},{type:a,value:" form implicitly assigns the "},{type:b,tag:d,props:{},children:[{type:a,value:r}]},{type:a,value:" operand as the "},{type:b,tag:d,props:{},children:[{type:a,value:N}]},{type:a,value:" register.\nTherefore, you only need to specify the "},{type:b,tag:d,props:{},children:[{type:a,value:v}]},{type:a,value:" operator.\nThe effects of the instruction will be similar to the two-operand form."}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"We will leave explanation of "},{type:b,tag:l,props:{},children:[{type:a,value:"three-operand"}]},{type:a,value:" form as a exercise of "},{type:b,tag:f,props:{href:"https:\u002F\u002Fwww.felixcloutier.com\u002Fx86\u002Fimul",rel:["nofollow","noopener","noreferrer"],target:"_blank"},children:[{type:a,value:"documentation"}]},{type:a,value:" reading to you."}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"Here, you can see all three forms of the instruction being used.\nBe sure to step through the code and predict the result of each instruction before it runs."}]},{type:a,value:c},{type:b,tag:H,props:{"initial-code":"\nmov rax, 5\nmov rbx, 2\nimul rax, rbx\nmov rax, 2\nmov rbx, 3\nimul rbx\nmov rax, 0\nmov rbx, 3\nimul rax, rbx, 3\n"},children:[{type:a,value:I}]},{type:a,value:c},{type:b,tag:ad,props:{id:ae},children:[{type:b,tag:f,props:{href:"#overflows",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:ae}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"One key difference that the "},{type:b,tag:l,props:{},children:[{type:a,value:J}]},{type:a,value:" form has in "},{type:b,tag:d,props:{},children:[{type:a,value:C}]},{type:a,value:" is tht it is the only one that can support an overflow of the "},{type:b,tag:d,props:{},children:[{type:a,value:v}]},{type:a,value:" register.\nAs we know, the operands we have current support up to 64-bits of data.\nHowever, multiplying 2 64-bit values could lead to a value larger than 64-bits.\nUsually, the value is "},{type:b,tag:l,props:{},children:[{type:a,value:"truncated"}]},{type:a,value:" to 64-bits, meaning that the calculation will be done correctly, but any bits beyond 64-bits will just be removed and ignored."}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"For the "},{type:b,tag:l,props:{},children:[{type:a,value:J}]},{type:a,value:" form of "},{type:b,tag:d,props:{},children:[{type:a,value:C}]},{type:a,value:", it will set "},{type:b,tag:d,props:{},children:[{type:a,value:"rdx"}]},{type:a,value:" to the bits of the calculation that exceed 64-bits.\nThis allows for greater range of calculation."}]},{type:a,value:c},{type:b,tag:ad,props:{id:K},children:[{type:b,tag:f,props:{href:"#mul",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:K}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:b,tag:d,props:{},children:[{type:a,value:K}]},{type:a,value:" is very similar to "},{type:b,tag:l,props:{},children:[{type:a,value:J}]},{type:a,value:" "},{type:b,tag:d,props:{},children:[{type:a,value:C}]},{type:a,value:", except that the operands are treated as unsigned values."}]},{type:a,value:c},{type:b,tag:t,props:{id:X},children:[{type:b,tag:f,props:{href:"#idivdiv",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:Y}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:b,tag:d,props:{},children:[{type:a,value:"idiv"}]},{type:a,value:s},{type:b,tag:d,props:{},children:[{type:a,value:m}]},{type:a,value:" are used for division ("},{type:b,tag:d,props:{},children:[{type:a,value:ac}]},{type:a,value:").\nSimilar to "},{type:b,tag:d,props:{},children:[{type:a,value:C}]},{type:a,value:s},{type:b,tag:d,props:{},children:[{type:a,value:K}]},{type:a,value:", they are the signed and unsigned versions respectively."}]},{type:a,value:c},{type:b,tag:E,props:{id:Z},children:[{type:b,tag:f,props:{href:"#binary-operators",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:_}]},{type:a,value:c},{type:b,tag:t,props:{id:x},children:[{type:b,tag:f,props:{href:"#not",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:x}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:B},{type:b,tag:d,props:{},children:[{type:a,value:x}]},{type:a,value:" instruction takes one operand, and performs a binary NOT.\nAlso known as one's complement negation, or \"flipping all the bits\"."}]},{type:a,value:c},{type:b,tag:t,props:{id:y},children:[{type:b,tag:f,props:{href:"#and",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:y}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:B},{type:b,tag:d,props:{},children:[{type:a,value:y}]},{type:a,value:P},{type:b,tag:d,props:{},children:[{type:a,value:r}]},{type:a,value:s},{type:b,tag:d,props:{},children:[{type:a,value:v}]},{type:a,value:" and performs a binary AND."}]},{type:a,value:c},{type:b,tag:t,props:{id:z},children:[{type:b,tag:f,props:{href:"#or",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:z}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:B},{type:b,tag:d,props:{},children:[{type:a,value:z}]},{type:a,value:P},{type:b,tag:d,props:{},children:[{type:a,value:r}]},{type:a,value:s},{type:b,tag:d,props:{},children:[{type:a,value:v}]},{type:a,value:" and performs a binary OR."}]},{type:a,value:c},{type:b,tag:t,props:{id:A},children:[{type:b,tag:f,props:{href:"#xor",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:A}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:B},{type:b,tag:d,props:{},children:[{type:a,value:A}]},{type:a,value:P},{type:b,tag:d,props:{},children:[{type:a,value:r}]},{type:a,value:s},{type:b,tag:d,props:{},children:[{type:a,value:v}]},{type:a,value:" and performs a binary exclusive-OR."}]},{type:a,value:c},{type:b,tag:H,props:{"initial-code":"\nmov rax, 0\nnot rax\nmov rax, 3\nmov rbx, 6\nand rax, rbx\nmov rax, 1\nmov rbx, 2\nor rax, rbx\nmov rax, 3\nmov rbx, 6\nxor rax, rbx\n"},children:[{type:a,value:I}]},{type:a,value:c},{type:b,tag:E,props:{id:$},children:[{type:b,tag:f,props:{href:"#unare-quiz-1",ariaHidden:g,tabIndex:h},children:[{type:b,tag:i,props:{className:[j,k]},children:[]}]},{type:a,value:aa}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"To test your knowledge thus far, we've prepared our special "},{type:b,tag:l,props:{},children:[{type:a,value:af}]},{type:a,value:" challenges!\nTry to understand the assembly snippet below, and write the corresponding C code that could generate such a assembly snippet."}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"Few things to note:"}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"The first and last few instructions can be ignored as they are instructions preparing the stack, generated by the compiler."}]},{type:a,value:c},{type:b,tag:m,props:{className:[o]},children:[{type:b,tag:p,props:{className:[q,F]},children:[{type:b,tag:d,props:{},children:[{type:a,value:"push rbp\nmov rbp, rsp\n...\npop rbp\nret\n"}]}]}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"The first 6 arguments of a function are passed in the "},{type:b,tag:d,props:{},children:[{type:a,value:"rdi, rsi, rdx, rcx, r8, r9"}]},{type:a,value:" registers.\nThe return value of a function is copied into "},{type:b,tag:d,props:{},children:[{type:a,value:N}]},{type:a,value:" before the function returns."}]},{type:a,value:c},{type:b,tag:e,props:{},children:[{type:a,value:"With this knowledge, give this problem a try!"}]},{type:a,value:c},{type:b,tag:af,props:{"chall-id":"easy-1"},children:[{type:a,value:c}]},{type:a,value:c},{type:b,tag:"spoiler",props:{title:"Click for answer"},children:[{type:a,value:c},{type:b,tag:m,props:{className:[o]},children:[{type:b,tag:p,props:{className:[q,F]},children:[{type:b,tag:d,props:{},children:[{type:a,value:"int foo(int a){\n    return a+1;\n}\n"}]}]}]},{type:a,value:c}]}]},dir:ag,path:"\u002Flessons\u002Fasm-x86-64\u002Foperators",extension:".md",createdAt:"2021-09-30T15:05:20.212Z",updatedAt:"2021-09-30T15:05:20.213Z"},module:{slug:"asm-x86-64",title:D,desc:"Learn about the assembly language understood by our home computers",diff:"Easy",order:w,toc:[],dir:"\u002Flessons",path:ag},prev:{slug:"memory",module:D,title:"Memory",desc:"Download more RAM!"},next:{slug:"control-flow",module:D,title:"Control Flow",desc:"Jumping around"},isLesson:Q,title:"Operators | ASM (x86-64)",challenges:[]}],fetch:{},mutations:void 0}}("text","element","\n","code","p","a","true",-1,"span","icon","icon-link","strong","div",3,"nuxt-content-highlight","pre","line-numbers","src"," and ","h3","sub","dst",2,"not","and","or","xor","The ","imul","ASM (x86-64)","h2","language-text","add","mini-omulator","\n\n\n","one-operand","mul","em","language-nasm","rax","li"," instruction take two operands ",true,"basic-operator-syntax","Basic operator syntax","arithmetic-operators","Arithmetic Operators","imulmul","imul\u002Fmul","idivdiv","idiv\u002Fdiv","binary-operators","Binary Operators","unare-quiz-1","Unare Quiz #1"," (","*","h4","overflows","unare","\u002Flessons\u002Fasm-x86-64")));