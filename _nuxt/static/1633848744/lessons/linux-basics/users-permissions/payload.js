__NUXT_JSONP__("/lessons/linux-basics/users-permissions", (function(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,_,$,aa,ab,ac,ad,ae,af,ag,ah,ai,aj,ak,al,am,an,ao,ap,aq,ar,as,at,au,av,aw,ax,ay,az,aA,aB,aC,aD,aE,aF,aG,aH,aI,aJ,aK,aL,aM,aN,aO,aP,aQ,aR,aS,aT,aU,aV,aW,aX){return {data:[{content:{slug:"users-permissions",layout:"lesson",module:ad,title:"Users and Permissions",desc:"Basic security features across Linux distributions",order:6,toc:[{id:t,depth:_,text:t},{id:an,depth:N,text:ao},{id:ap,depth:N,text:aq},{id:J,depth:N,text:J},{id:ar,depth:N,text:as},{id:n,depth:_,text:n},{id:at,depth:_,text:au},{id:av,depth:N,text:ae},{id:aw,depth:N,text:ax},{id:ay,depth:_,text:az},{id:aA,depth:N,text:aB},{id:aC,depth:N,text:aD},{id:aE,depth:_,text:aF}],body:{type:n,children:[{type:b,tag:h,props:{},children:[{type:a,value:"If you've done an introductory operating systems (OS) class before, you may know that one responsibility of a modern multi-user operating system is to handle security boundaries between different users. Such features are required so that multiple users can work harmoniously with a single device, like a family sharing a home computer or a large organisation sharing a complex cloud server."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"Amongst Linux-based OSes, the security implementations are similar, and it's crucial that we understand them to secure our systems, and circumvent these protections \u003E:)."}]},{type:a,value:e},{type:b,tag:$,props:{id:t},children:[{type:b,tag:o,props:{href:"#id",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:t}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"One core concept of Linux security is that of the "},{type:b,tag:g,props:{},children:[{type:a,value:t}]},{type:a,value:". There are multiple types of "},{type:b,tag:g,props:{},children:[{type:a,value:t}]},{type:a,value:"s (group\u002Fuser, real\u002Feffective), but the general idea is that ids are numerical values that represent a user or group of users."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"We can view the various "},{type:b,tag:g,props:{},children:[{type:a,value:t}]},{type:a,value:"s of our current user using the self-explanatory "},{type:b,tag:g,props:{},children:[{type:a,value:t}]},{type:a,value:" command."}]},{type:a,value:e},{type:b,tag:w,props:{className:[x]},children:[{type:b,tag:u,props:{className:[y,O]},children:[{type:b,tag:g,props:{},children:[{type:a,value:U},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:t}]},{type:a,value:e},{type:b,tag:c,props:{className:[d,K,L]},children:[{type:a,value:af}]},{type:b,tag:c,props:{className:[d,H]},children:[{type:a,value:M}]},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:V}]},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:z}]},{type:a,value:P},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:A}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,K,L]},children:[{type:a,value:ai}]},{type:b,tag:c,props:{className:[d,H]},children:[{type:a,value:M}]},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:V}]},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:z}]},{type:a,value:P},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:A}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,K,L]},children:[{type:a,value:J}]},{type:b,tag:c,props:{className:[d,H]},children:[{type:a,value:M}]},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:V}]},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:z}]},{type:a,value:P},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:A}]},{type:a,value:",4"},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:z}]},{type:a,value:"adm"},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:A}]},{type:a,value:e}]}]}]},{type:a,value:e},{type:b,tag:Q,props:{id:an},children:[{type:b,tag:o,props:{href:"#uid-user-id",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:ao}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"The uid (user id) is a "},{type:b,tag:l,props:{},children:[{type:a,value:"unique"}]},{type:a,value:" integer that represents the user. Being unique, no other user would be represented by the same number.\nThis is similar to passport numbers in the real-world, the number represents the passport that is tied with your identity, and no other person should share the passport number with you."}]},{type:a,value:e},{type:b,tag:Q,props:{id:ap},children:[{type:b,tag:o,props:{href:"#gid-group-id",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:aq}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"The gid (group id) is the identifying integer that represents the user's "},{type:b,tag:l,props:{},children:[{type:a,value:"primary"}]},{type:a,value:" group.\nGroups are just a collection of users, that can then be assigned permissions to perform certain actions.\nThis way, each individual user of the group does not need to be given the permissions separately."}]},{type:a,value:e},{type:b,tag:Q,props:{id:J},children:[{type:b,tag:o,props:{href:"#groups",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:J}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:aG},{type:b,tag:g,props:{},children:[{type:a,value:J}]},{type:a,value:" field will list all groups that the user belongs to, not just the primary group of the user. The secondary (non-primary) groups are usually assigned to a user "},{type:b,tag:T,props:{},children:[{type:a,value:"after"}]},{type:a,value:" creation, but function simiarly."}]},{type:a,value:e},{type:b,tag:Q,props:{id:ar},children:[{type:b,tag:o,props:{href:"#effective-vs-real",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:as}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"On top of this, rarely the "},{type:b,tag:g,props:{},children:[{type:a,value:t}]},{type:a,value:" command may mention the "},{type:b,tag:T,props:{},children:[{type:a,value:"effective"}]},{type:a,value:" id of a user.\nThis is in cases where the user was granted the effective id of another user, in order to perform operations that only the other user is able to perform."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"This can be done through using the setuid bit, which will be explained shortly."}]},{type:a,value:e},{type:b,tag:$,props:{id:n},children:[{type:b,tag:o,props:{href:"#root",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:n}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:aG},{type:b,tag:g,props:{},children:[{type:a,value:n}]},{type:a,value:" user is a special user in most Linux operating systems. This user has a uid of "},{type:b,tag:g,props:{},children:[{type:a,value:aa}]},{type:a,value:".\nThe "},{type:b,tag:g,props:{},children:[{type:a,value:n}]},{type:a,value:" user is meant to be the power-user\u002Fadmin, and should be able perform the most operations out of all the users."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"In general, most users will not be logging in to the "},{type:b,tag:g,props:{},children:[{type:a,value:n}]},{type:a,value:" user (with exception of distros like Kali).\nInstead, if we wish to perform administrative actions with the power of "},{type:b,tag:g,props:{},children:[{type:a,value:n}]},{type:a,value:", we use the "},{type:b,tag:g,props:{},children:[{type:a,value:W}]},{type:a,value:" command instead, which allows us to run commands as if we were "},{type:b,tag:g,props:{},children:[{type:a,value:n}]},{type:a,value:aH}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"The syntax is as follows:"}]},{type:a,value:e},{type:b,tag:w,props:{className:[x]},children:[{type:b,tag:u,props:{className:[y,aj]},children:[{type:b,tag:g,props:{},children:[{type:a,value:"sudo \u003Ccommand to run\u003E\n"}]}]}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"For example:"}]},{type:a,value:e},{type:b,tag:w,props:{className:[x]},children:[{type:b,tag:u,props:{className:[y,O]},children:[{type:b,tag:g,props:{},children:[{type:a,value:U},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:t}]},{type:a,value:e},{type:b,tag:c,props:{className:[d,K,L]},children:[{type:a,value:af}]},{type:b,tag:c,props:{className:[d,H]},children:[{type:a,value:M}]},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:V}]},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:z}]},{type:a,value:P},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:A}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,K,L]},children:[{type:a,value:ai}]},{type:b,tag:c,props:{className:[d,H]},children:[{type:a,value:M}]},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:V}]},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:z}]},{type:a,value:P},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:A}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,K,L]},children:[{type:a,value:J}]},{type:b,tag:c,props:{className:[d,H]},children:[{type:a,value:M}]},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:V}]},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:z}]},{type:a,value:P},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:A}]},{type:a,value:",27"},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:z}]},{type:a,value:W},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:A}]},{type:a,value:"\n\n$ "},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:W}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:t}]},{type:a,value:e},{type:b,tag:c,props:{className:[d,K,L]},children:[{type:a,value:af}]},{type:b,tag:c,props:{className:[d,H]},children:[{type:a,value:M}]},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:aa}]},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:z}]},{type:a,value:n},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:A}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,K,L]},children:[{type:a,value:ai}]},{type:b,tag:c,props:{className:[d,H]},children:[{type:a,value:M}]},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:aa}]},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:z}]},{type:a,value:n},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:A}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,K,L]},children:[{type:a,value:J}]},{type:b,tag:c,props:{className:[d,H]},children:[{type:a,value:M}]},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:aa}]},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:z}]},{type:a,value:n},{type:b,tag:c,props:{className:[d,k]},children:[{type:a,value:A}]},{type:a,value:e}]}]}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"As this is a powerful capability which allows any user to elevate to "},{type:b,tag:g,props:{},children:[{type:a,value:n}]},{type:a,value:" permissions, only users belonging to the "},{type:b,tag:T,props:{},children:[{type:a,value:"sudoers"}]},{type:a,value:" ("},{type:b,tag:g,props:{},children:[{type:a,value:W}]},{type:a,value:") group will be allowed to use the "},{type:b,tag:g,props:{},children:[{type:a,value:W}]},{type:a,value:" command to run commands.\nFurthermore, even users that are allowed to use "},{type:b,tag:g,props:{},children:[{type:a,value:W}]},{type:a,value:" could be granted fine-grain permissions on what exact commands they are allowed to run with sudo."}]},{type:a,value:e},{type:b,tag:$,props:{id:at},children:[{type:b,tag:o,props:{href:"#permissions",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:au}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"Now that we understand how users can be identified by their "},{type:b,tag:l,props:{},children:[{type:a,value:af}]},{type:a,value:aI},{type:b,tag:l,props:{},children:[{type:a,value:J}]},{type:a,value:", let's understand how permissions are given to them.\nFirst, we can create a simple text file."}]},{type:a,value:e},{type:b,tag:w,props:{className:[x]},children:[{type:b,tag:u,props:{className:[y,O]},children:[{type:b,tag:g,props:{},children:[{type:a,value:U},{type:b,tag:c,props:{className:[d,"builtin","class-name"]},children:[{type:a,value:"echo"}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,"string"]},children:[{type:a,value:"\"Hello, World\""}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,H]},children:[{type:a,value:"\u003E"}]},{type:a,value:" hello.txt\n"}]}]}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"To view permissions, we can use the "},{type:b,tag:g,props:{},children:[{type:a,value:v}]},{type:a,value:" command with the "},{type:b,tag:g,props:{},children:[{type:a,value:"-l"}]},{type:a,value:" (list) flag."}]},{type:a,value:e},{type:b,tag:w,props:{className:[x]},children:[{type:b,tag:u,props:{className:[y,O]},children:[{type:b,tag:g,props:{},children:[{type:a,value:U},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:v}]},{type:a,value:ab},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:B}]},{type:a,value:C},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:D}]},{type:a,value:E},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:F}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:G}]},{type:a,value:ag}]}]}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"Let's draw our attention to the "},{type:b,tag:g,props:{},children:[{type:a,value:"omu omu"}]},{type:a,value:" section of the output.\nThe first "},{type:b,tag:g,props:{},children:[{type:a,value:P}]},{type:a,value:" is the name of the "},{type:b,tag:l,props:{},children:[{type:a,value:"owner"}]},{type:a,value:" of the file.\nSince we created this file, it makes sense that the owner is our user, omu."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"The second "},{type:b,tag:g,props:{},children:[{type:a,value:P}]},{type:a,value:" refers to the primary group of the owner.\nAs we've shown earlier, our user's primary group is named omu as well, and this is reflected in the output."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"Understanding this, we can move on to the most important part of the output, the front section."}]},{type:a,value:e},{type:b,tag:w,props:{className:[x]},children:[{type:b,tag:u,props:{className:[y,aj]},children:[{type:b,tag:g,props:{},children:[{type:a,value:"-rw-rw-r--\n"}]}]}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"This output should be split into groups of 1-3-3-3 to be understood."}]},{type:a,value:aJ},{type:b,tag:aK,props:{},children:[{type:b,tag:aL,props:{},children:[{type:b,tag:ah,props:{},children:[{type:b,tag:R,props:{align:m},children:[{type:a,value:ae}]},{type:b,tag:R,props:{align:m},children:[{type:a,value:"User"}]},{type:b,tag:R,props:{align:m},children:[{type:a,value:aM}]},{type:b,tag:R,props:{align:m},children:[{type:a,value:aN}]}]}]},{type:b,tag:aO,props:{},children:[{type:b,tag:ah,props:{},children:[{type:b,tag:S,props:{align:m},children:[{type:b,tag:g,props:{},children:[{type:a,value:X}]}]},{type:b,tag:S,props:{align:m},children:[{type:b,tag:g,props:{},children:[{type:a,value:aP}]}]},{type:b,tag:S,props:{align:m},children:[{type:b,tag:g,props:{},children:[{type:a,value:aP}]}]},{type:b,tag:S,props:{align:m},children:[{type:b,tag:g,props:{},children:[{type:a,value:"r--"}]}]}]}]}]},{type:a,value:e},{type:b,tag:Q,props:{id:av},children:[{type:b,tag:o,props:{href:"#file-type",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:ae}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"The file type can either be a regular file ("},{type:b,tag:g,props:{},children:[{type:a,value:X}]},{type:a,value:"), a directory ("},{type:b,tag:g,props:{},children:[{type:a,value:"d"}]},{type:a,value:") or a link ("},{type:b,tag:g,props:{},children:[{type:a,value:"i"}]},{type:a,value:"). We have covered files and directories before, and links are a special type of file that link to another file."}]},{type:a,value:e},{type:b,tag:Q,props:{id:aw},children:[{type:b,tag:o,props:{href:"#usergroupothers",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:ax}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"These three sections represent the permissions that 3 different groups have for the current file. The "},{type:b,tag:l,props:{},children:[{type:a,value:"user\u002Fowner"}]},{type:a,value:" permissions to the file, the permissions that members of the "},{type:b,tag:l,props:{},children:[{type:a,value:"owner's group"}]},{type:a,value:" has, and the permissions that all "},{type:b,tag:l,props:{},children:[{type:a,value:"other"}]},{type:a,value:" users will have."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"Each permission is represented by three characters, representing the "},{type:b,tag:l,props:{},children:[{type:a,value:"read"}]},{type:a,value:", "},{type:b,tag:l,props:{},children:[{type:a,value:"write"}]},{type:a,value:aI},{type:b,tag:l,props:{},children:[{type:a,value:"execute"}]},{type:a,value:" permissions for the file.\nThe read and write permissions are self-explanatory, and determine whether there is permission to read the contents of the file, or to write to the file."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"The execute permission determines whether the file is an exectuable, and whether the user has permissions to execute the file. Simple text data should not be made executable, while scripts or binary executables (like "},{type:b,tag:g,props:{},children:[{type:a,value:"\u002Fbin\u002Fls"}]},{type:a,value:") should be made executable for the allowed users."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"In the case of our "},{type:b,tag:g,props:{},children:[{type:a,value:"hello.txt"}]},{type:a,value:" file, it has been automatically created with these permissions."}]},{type:a,value:e},{type:b,tag:"ul",props:{},children:[{type:a,value:e},{type:b,tag:aQ,props:{},children:[{type:a,value:"Owner\u002FMembers of the owner's group "},{type:b,tag:T,props:{},children:[{type:a,value:aR}]},{type:a,value:" read and write to the file, but "},{type:b,tag:T,props:{},children:[{type:a,value:aS}]},{type:a,value:" execute it"}]},{type:a,value:e},{type:b,tag:aQ,props:{},children:[{type:a,value:"All other users "},{type:b,tag:T,props:{},children:[{type:a,value:aR}]},{type:a,value:" read the file, but "},{type:b,tag:T,props:{},children:[{type:a,value:aS}]},{type:a,value:" write or execute the file"}]},{type:a,value:e}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"In tabular form, the file's permissions are like so."}]},{type:a,value:aJ},{type:b,tag:aK,props:{},children:[{type:b,tag:aL,props:{},children:[{type:b,tag:ah,props:{},children:[{type:b,tag:R,props:{align:m},children:[{type:a,value:ae}]},{type:b,tag:R,props:{align:m},children:[{type:a,value:"User\u002FOwner"}]},{type:b,tag:R,props:{align:m},children:[{type:a,value:aM}]},{type:b,tag:R,props:{align:m},children:[{type:a,value:aN}]}]}]},{type:b,tag:aO,props:{},children:[{type:b,tag:ah,props:{},children:[{type:b,tag:S,props:{align:m},children:[{type:a,value:"Regular file"}]},{type:b,tag:S,props:{align:m},children:[{type:b,tag:l,props:{},children:[{type:a,value:ak}]},{type:a,value:X},{type:b,tag:l,props:{},children:[{type:a,value:aT}]},{type:a,value:aU}]},{type:b,tag:S,props:{align:m},children:[{type:b,tag:l,props:{},children:[{type:a,value:ak}]},{type:a,value:X},{type:b,tag:l,props:{},children:[{type:a,value:aT}]},{type:a,value:aU}]},{type:b,tag:S,props:{align:m},children:[{type:b,tag:l,props:{},children:[{type:a,value:ak}]},{type:a,value:"-NO WRITE-NO EXECUTE"}]}]}]}]},{type:a,value:e},{type:b,tag:"quiz",props:{},children:[{type:a,value:"\n    "},{type:b,tag:"option-quiz",props:{answer:"2",":options":"['Yes', 'No']"},children:[{type:a,value:"\n        Given the following permissions:\n        "},{type:b,tag:u,props:{},children:[{type:b,tag:g,props:{},children:[{type:a,value:"\n    -rwxrwxr-x\n        "}]}]},{type:a,value:"\n        can a non-owner modify the executable?\n    "}]},{type:a,value:e}]},{type:a,value:e},{type:b,tag:$,props:{id:ay},children:[{type:b,tag:o,props:{href:"#modifying-permissions",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:az}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"The easiest way to change permissions is to add or remove them for everybody. The command to use is "},{type:b,tag:g,props:{},children:[{type:a,value:I}]},{type:a,value:aH}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"The syntax is as follows"}]},{type:a,value:e},{type:b,tag:w,props:{className:[x]},children:[{type:b,tag:u,props:{className:[y,aj]},children:[{type:b,tag:g,props:{},children:[{type:a,value:"chmod \u003Cpermission change\u003E \u003Cfile\u003E\n"}]}]}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"Showing some examples will be better than explaining. So here are a few examples:"}]},{type:a,value:e},{type:b,tag:w,props:{className:[x]},children:[{type:b,tag:u,props:{className:[y,O]},children:[{type:b,tag:g,props:{},children:[{type:b,tag:c,props:{className:[d,Y]},children:[{type:a,value:"# Check current permissions"}]},{type:a,value:Z},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:v}]},{type:a,value:ab},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:B}]},{type:a,value:C},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:D}]},{type:a,value:E},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:F}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:G}]},{type:a,value:al},{type:b,tag:c,props:{className:[d,Y]},children:[{type:a,value:"# Disallow ALL from reading (r)"}]},{type:a,value:Z},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:I}]},{type:a,value:" -r hello.txt\n$ "},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:v}]},{type:a,value:" -l hello.txt\n--w--w---- "},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:B}]},{type:a,value:C},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:D}]},{type:a,value:E},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:F}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:G}]},{type:a,value:aV},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:ac}]},{type:a,value:" hello.txt\ncat: hello.txt: Permission denied\n\n"},{type:b,tag:c,props:{className:[d,Y]},children:[{type:a,value:"# Allow ALL to read (r)"}]},{type:a,value:Z},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:I}]},{type:a,value:" +r hello.txt\n$ "},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:v}]},{type:a,value:ab},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:B}]},{type:a,value:C},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:D}]},{type:a,value:E},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:F}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:G}]},{type:a,value:aV},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:ac}]},{type:a,value:" hello.txt\nHello, World\n"}]}]}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"To do the same for write(w) and execute(x) permissions, the "},{type:b,tag:g,props:{},children:[{type:a,value:"+r\u002F-r"}]},{type:a,value:" just needs to replaced accordingly."}]},{type:a,value:e},{type:b,tag:Q,props:{id:aA},children:[{type:b,tag:o,props:{href:"#changing-permissions-for-specific-subgroup",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:aB}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"However, sometimes more fine-grained control is required.\nFor example, we may only want to allow the owner to read and write to the file, while disallowing others from reading or writing."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"To do so, we can prepend the group in front of the "},{type:b,tag:g,props:{},children:[{type:a,value:"+"}]},{type:a,value:" or "},{type:b,tag:g,props:{},children:[{type:a,value:X}]},{type:a,value:" in "},{type:b,tag:g,props:{},children:[{type:a,value:I}]},{type:a,value:"'s command-line syntax."}]},{type:a,value:e},{type:b,tag:w,props:{className:[x]},children:[{type:b,tag:u,props:{className:[y,O]},children:[{type:b,tag:g,props:{},children:[{type:a,value:U},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:v}]},{type:a,value:ab},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:B}]},{type:a,value:C},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:D}]},{type:a,value:E},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:F}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:G}]},{type:a,value:aW},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:I}]},{type:a,value:" o-r hello.txt\n$ "},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:v}]},{type:a,value:" -l hello.txt\n-rw-rw---- "},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:B}]},{type:a,value:C},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:D}]},{type:a,value:E},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:F}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:G}]},{type:a,value:ag}]}]}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"As can be seen, we have removed ("},{type:b,tag:l,props:{},children:[{type:a,value:X}]},{type:a,value:") the "},{type:b,tag:l,props:{},children:[{type:a,value:"r"}]},{type:a,value:"ead permissions from the "},{type:b,tag:l,props:{},children:[{type:a,value:"o"}]},{type:a,value:"thers group (non-owners). If we want to further restrict it such that even users of the owner's group are unable to read or write to the file, we can do so too."}]},{type:a,value:e},{type:b,tag:w,props:{className:[x]},children:[{type:b,tag:u,props:{className:[y,O]},children:[{type:b,tag:g,props:{},children:[{type:a,value:U},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:I}]},{type:a,value:" g-r hello.txt\n$ "},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:v}]},{type:a,value:" -l hello.txt\n-rw--w---- "},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:B}]},{type:a,value:C},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:D}]},{type:a,value:E},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:F}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:G}]},{type:a,value:aW},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:I}]},{type:a,value:" g-w hello.txt\n$ "},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:v}]},{type:a,value:" -l hello.txt\n-rw------- "},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:B}]},{type:a,value:C},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:D}]},{type:a,value:E},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:F}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:G}]},{type:a,value:ag}]}]}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"Now, only the owner themselves can read\u002Fwrite the file."}]},{type:a,value:e},{type:b,tag:Q,props:{id:aC},children:[{type:b,tag:o,props:{href:"#numeric-method",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:aD}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"There is an additional numeric method to modify permissions.\nBut we will not cover this as it is less intuitive to understand.\nHowever, this can be quite useful to learn if you wish to be a power-user, "},{type:b,tag:o,props:{href:"https:\u002F\u002Flinuxize.com\u002Fpost\u002Fchmod-command-in-linux\u002F#numeric-method",rel:["nofollow","noopener","noreferrer"],target:"_blank"},children:[{type:a,value:"this"}]},{type:a,value:" will be a good reference to understand this method."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"Here are some examples:"}]},{type:a,value:e},{type:b,tag:w,props:{className:[x]},children:[{type:b,tag:u,props:{className:[y,O]},children:[{type:b,tag:g,props:{},children:[{type:b,tag:c,props:{className:[d,Y]},children:[{type:a,value:"# Remove ALL permissions"}]},{type:a,value:Z},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:I}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:aa}]},{type:a,value:am},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:v}]},{type:a,value:" -l hello.txt\n---------- "},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:B}]},{type:a,value:C},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:D}]},{type:a,value:E},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:F}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:G}]},{type:a,value:al},{type:b,tag:c,props:{className:[d,Y]},children:[{type:a,value:"# Add ALL permissions for ALL users"}]},{type:a,value:Z},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:I}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:"777"}]},{type:a,value:am},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:v}]},{type:a,value:" -l hello.txt\n-rwxrwxrwx "},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:B}]},{type:a,value:C},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:D}]},{type:a,value:E},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:F}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:G}]},{type:a,value:al},{type:b,tag:c,props:{className:[d,Y]},children:[{type:a,value:"# Figure this out!"}]},{type:a,value:Z},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:I}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:"664"}]},{type:a,value:am},{type:b,tag:c,props:{className:[d,i]},children:[{type:a,value:v}]},{type:a,value:ab},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:B}]},{type:a,value:C},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:D}]},{type:a,value:E},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:F}]},{type:a,value:j},{type:b,tag:c,props:{className:[d,f]},children:[{type:a,value:G}]},{type:a,value:ag}]}]}]},{type:a,value:e},{type:b,tag:$,props:{id:aE},children:[{type:b,tag:o,props:{href:"#setuid-permissions",ariaHidden:p,tabIndex:q},children:[{type:b,tag:c,props:{className:[r,s]},children:[]}]},{type:a,value:aF}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"We mentioned this earlier, but setuid (set user ID on execution) permissions are a special type of permission. The group equivalent (setgid) exists as well."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"Generally, when we run an executable (e.g. "},{type:b,tag:g,props:{},children:[{type:a,value:ac}]},{type:a,value:"), the exectuable will be run with the permissions of the user running.\nTherefore even if the "},{type:b,tag:g,props:{},children:[{type:a,value:"root (uid-0)"}]},{type:a,value:" created the "},{type:b,tag:g,props:{},children:[{type:a,value:ac}]},{type:a,value:" binary, the files that can be read using "},{type:b,tag:g,props:{},children:[{type:a,value:ac}]},{type:a,value:" are limited to those allowed for the current user.\nThis makes sense as the user should not be able to have higher privileges than what's allowed to their user by default."}]},{type:a,value:e},{type:b,tag:h,props:{},children:[{type:a,value:"However, there are certain scenarios where the user may need elevated privileges to do useful work."}]}]},dir:aX,path:"\u002Flessons\u002Flinux-basics\u002Fusers-permissions",extension:".md",createdAt:"2021-08-29T08:54:08.938Z",updatedAt:"2021-09-26T11:18:02.002Z"},module:{slug:"linux-basics",title:ad,desc:"Learn the basics of operating a Linux-based operating system (OS) and take your first steps in exploitation in a Linux environment!",diff:"Easy",order:1,toc:[],dir:"\u002Flessons",path:aX},prev:{slug:"execution",module:ad,title:"Execution",desc:"Basic understanding of how programs are executed"},next:{slug:"tcp-pwntools",module:ad,title:"TCP and Pwntools",desc:"Basics of networking in a Linux environment"},isLesson:true,title:"Users and Permissions | Linux Basics",challenges:[]}],fetch:{},mutations:void 0}}("text","element","span","token","\n","number","code","p","function"," ","punctuation","strong","center","root","a","true",-1,"icon","icon-link","id","pre","ls","div","nuxt-content-highlight","line-numbers","(",")","1"," omu omu ","13"," Jul ","30","14","operator","chmod","groups","assign-left","variable","=",3,"language-bash","omu","h3","th","td","em","$ ","1000","sudo","-","comment","\n$ ",2,"h2","0"," -l hello.txt\n-rw-rw-r-- ","cat","Linux Basics","File Type","uid",":26 hello.txt\n","tr","gid","language-text","READ",":26 hello.txt\n\n"," hello.txt\n$ ","uid-user-id","uid (User ID)","gid-group-id","gid (Group ID)","effective-vs-real","Effective VS Real","permissions","Permissions","file-type","usergroupothers","User\u002FGroup\u002FOthers","modifying-permissions","Modifying Permissions","changing-permissions-for-specific-subgroup","Changing permissions for specific subgroup","numeric-method","Numeric method","setuid-permissions","setuid permissions","The ","."," and ","\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n","table","thead","Group","Others","tbody","rw-","li","can","cannot","WRITE","-NO EXECUTE",":26 hello.txt\n$ ",":26 hello.txt\n\n$ ","\u002Flessons\u002Flinux-basics")));