if(!_.tag_cloud_part){_.tag_cloud_part=1;(function($){var Asa=function(a){var b=new $.wh;b.parent(a);return b},Bsa=function(a,b){a.Zn=b;a.Zn.push("#000");a.$V=!!b;a.reset()},J7=function(a,b){$.Cx.call(this);this.Ga("tagCloud");this.Er=["x","value"];this.ea="category";this.Ja=this.P=window.NaN;var c=[$.Z.k8,$.Z.c$],d={};$.T(d,[["fill",16,1],["stroke",16,1],["fontFamily",16388,1],["fontStyle",16388,1],["fontVariant",16388,1],["fontWeight",16388,1],["fontSize",16388,1]]);var e={};$.T(e,[["fill",0,0],["stroke",0,0],["fontFamily",0,0],["fontStyle",0,0],["fontVariant",
0,0],["fontWeight",0,0],["fontSize",0,0]]);this.ca=new $.my(this,d,$.hm,c);this.za=new $.my(this,e,$.Ao,c);this.Ea=new $.my(this,e,$.Bo,c);this.ca.Ga(this.oa);$.W(this,"normal",this.ca);$.W(this,"hovered",this.za);$.W(this,"selected",this.Ea);this.state=new $.jx(this);this.data(a||null,b);$.T(this.ua,[["mode",4,1],["fromAngle",8192,1],["toAngle",8192,1],["anglesCount",8192,1],["textSpacing",4,1]]);this.Ta()},K7=function(a,b){$.z(b)?(a.Cd("fill",b),a.Cd("fill-opacity",1)):(a.Cd("fill",b.color),a.Cd("fill-opacity",
b.opacity))},L7=function(a,b){$.z(b)?(a.Cd("stroke",b),a.Cd("stroke-opacity",1),a.Cd("stroke-width",1)):(a.Cd("stroke",b.color),a.Cd("stroke-opacity",b.opacity||1),a.Cd("stroke-width",b.thickness||1))},M7=function(a,b,c){if(c!=$.hm){var d=c==$.Ao?a.za:a.Ea;d=d.g(b);var e=$.zo(d);if(null!=d&&!$.E(d)&&!e)return d}var f=a.$().o("item");c=a.ca.g(b);var h=$.zo(c);if(null==c||h){switch(b){case "fontFamily":var k=f.font;break;case "fill":k=f.fill;break;case "stroke":k=f.stroke;break;case "fontStyle":k=f.style;
break;case "fontVariant":k=f.variant;break;case "fontWeight":k=f.weight;break;case "fontSize":k=f.size}c=k}else $.E(c)&&("fill"==b||"stroke"==b?k=a.He():(k=a.Ic(),k.sourceValue=c),c=c.call(k,k));if(d){if(e)return c*(0,window.parseFloat)(d)/100;"fill"==b||"stroke"==b?k=a.He(c):(k=a.Ic(),k.sourceValue=c);return d.call(k,k)}return c},Csa=function(a,b){if(b){var c=a.f/3,d=a.i/3,e=a.i/50,f=$.Va(e,~~d+1),h=$.Oa(f,function(a){a=$.ng().measure(b.text,{fontStyle:b.style,fontFamily:b.font,fontSize:a,fontWeight:b.weight,
fontVariant:b.variant});var e=$.Jo(a,"center");e=$.Jb($.bb(b.rotate),e.x,e.y);a=$.on(a)||[];e.transform(a,0,a,0,4);a=$.pn(a);e=a.width;a=a.height;return e>c||a>d?-1:e==c||a==d?0:1});0>h&&(h=~h-1);a.P=e;a.Ja=f[$.Za(h,0,f.length)]}},Dsa=function(a,b,c,d,e){if(!c.PE){var f=b.context,h=b.ratio;f.clearRect(0,0,2048/h,2048/h);var k=b=0,l=0,m=d.length;--e;for(var p=a.g("textSpacing");++e<m;){c=d[e];f.save();a="";"normal"!=c.style&&(a+=c.style+" ");"normal"!=c.weight&&(a+=c.weight+" ");"normal"!=c.variant&&
(a+=c.variant+" ");f.font=a+~~((c.size+1)/h)+"px "+c.font;a=f.measureText(c.text).width*h;var q=c.size<<1;if(c.rotate){var r=Math.sin($.bb(c.rotate)),t=Math.cos($.bb(c.rotate)),u=a*t,v=a*r;t*=q;a=q*r;a=Math.max(Math.abs(u+a),Math.abs(u-a))+31>>5<<5;q=~~Math.max(Math.abs(v+t),Math.abs(v-t))}else a=a+31>>5<<5;q>l&&(l=q);2048<=b+a&&(b=0,k+=l,l=0);if(2048<=k+q)break;f.translate((b+(a>>1))/h,(k+(q>>1))/h);c.rotate&&f.rotate($.bb(c.rotate));f.fillText(c.text,0,0);p&&(f.lineWidth=2*p,f.strokeText(c.text,
0,0));f.restore();c.width=a;c.height=q;c.yla=b;c.Cla=k;c.li=a>>1;c.Qe=q>>1;c.Gj=-c.li;c.ze=-c.Qe;c.M2=!0;b+=a}f=f.getImageData(0,0,2048/h,2048/h).data;for(h=[];0<=--e;)if(c=d[e],c.M2){a=c.width;l=a>>5;q=c.Qe-c.ze;for(m=0;m<q*l;m++)h[m]=0;b=c.yla;if(null==b)break;k=c.Cla;p=0;u=-1;for(v=0;v<q;v++){for(m=0;m<a;m++)r=f[2048*(k+v)+(b+m)<<2]?1<<31-m%32:0,h[l*v+(m>>5)]|=r,p|=r;p?u=v:(c.ze++,q--,v--,k++)}c.Qe=c.ze+u;c.PE=h.slice(0,(c.Qe-c.ze)*l)}}},Esa=function(a,b){var c=a[0],d=a[1];b.x+b.Gj<c.x&&(c.x=b.x+
b.Gj);b.y+b.ze<c.y&&(c.y=b.y+b.ze);b.x+b.li>d.x&&(d.x=b.x+b.li);b.y+b.Qe>d.y&&(d.y=b.y+b.Qe)},Fsa=function(a){var b=4*a.f/a.i,c=0,d=0;return function(a){var e=0>a?-1:1;switch(Math.sqrt(1+4*e*a)-e&3){case 0:c+=b;break;case 1:d+=4;break;case 2:c-=b;break;default:d-=4}return[c,d]}},Gsa=function(a){for(var b=[],c=-1;++c<a;)b[c]=0;return b},Hsa=function(a,b,c,d,e){for(var f=c.x,h=c.y,k=0,l,m;l=a.$a(k);){k+=1;m=~~l[0];l=~~l[1];if(Math.min(Math.abs(m),Math.abs(l))>=e)break;c.x=f+m;c.y=h+l;if(!(m=0>c.x+c.Gj||
0>c.y+c.ze||c.x+c.li>a.f||c.y+c.Qe>a.i)&&(m=d))a:{m=a.f;m>>=5;l=c.PE;var p=c.width>>5;var q=c.x-(p<<4);for(var r=q&127,t=32-r,u=c.Qe-c.ze,v=(c.y+c.ze)*m+(q>>5),w=0;w<u;w++){for(var x=q=0;x<=p;x++)if((q<<t|(x<p?(q=l[w*p+x])>>>r:0))&b[v+x]){m=!0;break a}v+=m}m=!1}if(!m&&(!d||c.x+c.li>d[0].x&&c.x+c.Gj<d[1].x&&c.y+c.Qe>d[0].y&&c.y+c.ze<d[1].y)){d=c.PE;e=c.width>>5;a=a.f>>5;m=c.x-(e<<4);f=m&127;h=32-f;k=c.Qe-c.ze;m=(c.y+c.ze)*a+(m>>5);for(p=0;p<k;p++){for(r=l=0;r<=e;r++)b[m+r]=b[m+r]|l<<h|(r<e?(l=d[p*
e+r])>>>f:0);m+=a}delete c.PE;return!0}}return!1},Isa=function(a){var b=a.$(),c=a.An(),d=a.qa,e=a.Zn,f=(0,window.parseFloat)(b.get("value")),h=b.get("category"),k=b.ma();if($.J(c,$.iz)&&$.n(h)){var l=h;b.o("category",h);b=a.ca.g("fill");$.E(b)&&(a={sourceColor:a.cc().nc(k),category:h},b=b.call(a,a));e.push($.Xb(b))}else a.vb?l=f:(b.o("category",void 0),l=$.Xb(M7(a,"fill",0)),e.push(l),l=$.C(l)?l.color:l,b.o("category",l));c.Xc(l);d.Xc(f)},Jsa=function(a,b){var c=new J7(a,b);c.GE(c.oa);return c},Ksa=
{Sra:"spiral",f9:"rect"};$.H(J7,$.Cx);$.Jq(J7,"fill stroke fontFamily fontStyle fontVariant fontWeight fontSize".split(" "),"normal");J7.prototype.sa=$.Cx.prototype.sa|258064;var N7={};$.vq(N7,[[0,"mode",function(a,b){return $.Ak(Ksa,a,b||"spiral")}],[0,"fromAngle",$.Eq],[0,"toAngle",$.Eq],[0,"anglesCount",$.Eq],[0,"textSpacing",$.Eq]]);$.U(J7,N7);$.g=J7.prototype;$.g.Ma=function(){return"tag-cloud"};$.g.wc=function(){return this};$.g.eh=function(){return!0};$.g.yk=function(){return!1};$.g.aj=function(){return!0};
$.g.Ue=function(){return[this]};$.g.be=function(a){var b=new $.HA(this,a);this.$().select(a)&&b.hy()&&(a=b.get("value")/this.Rg("sum"),b.La("yPercentOfTotal",$.Wm(100*a,2)),b.La("percentValue",a));return b};$.g.nq=function(){return null};$.g.$=function(){return this.sd||(this.sd=this.la.$())};$.g.Dc=function(){return this.sd=this.la.$()};
$.g.cc=function(a){if($.J(a,$.Os))return this.Hc($.Os,a),this;if($.J(a,$.Ls))return this.Hc($.Ls,a),this;$.C(a)&&"range"==a.type?this.Hc($.Os):($.C(a)||null==this.Fa)&&this.Hc($.Ls);return $.n(a)?(this.Fa.N(a),this):this.Fa};$.g.Hc=function(a,b){if($.J(this.Fa,a))b&&this.Fa.N(b);else{var c=!!this.Fa;$.pd(this.Fa);this.Fa=new a;$.W(this,"palette",this.Fa);this.Fa.Fp();b&&this.Fa.N(b);$.L(this.Fa,this.Of,this);c&&this.B(512,1)}};$.g.Of=function(a){$.X(a,2)&&this.B(65536,129)};
$.g.He=function(a){var b=this.$(),c=b.ma();a=a||this.cc().nc(c)||"blue";c={};var d=this.An(),e=b.get("value");b=b.o("category");c.value=e;c.category=b;if(d){e=$.J(d,$.iz)&&$.n(b)?b:e;if(this.vb||$.n(b))var f=d.Pq(e);$.Uc(c,{scaledColor:f,colorScale:this.vb})}c.sourceColor=a;return c};$.g.An=function(){return this.vb||this.Za||(this.Za=$.jz())};
$.g.Ic=function(){var a=this.$();this.me||(this.me=new $.Gw);this.me.lg(a).Li([this.be(a.ma()),this]);a={x:{value:a.get("x"),type:"string"},value:{value:a.get("value"),type:"number"},name:{value:a.get("name"),type:"string"},index:{value:a.ma(),type:"number"},chart:{value:this,type:""}};$.qv(this.me,a);return this.me};$.g.Qk=function(){return this.Ic()};$.g.bi=function(){var a=this.$().o("item");return{value:{x:this.na+a.x*this.Ia,y:this.Ca+a.y*this.Ia}}};$.g.ll=function(){};
$.g.mk=function(a,b){var c=this.$().o("item");if(c&&c.UC){var d=$.fm(a),e=$.Xb(M7(this,"fill",d)),f=$.Zb(M7(this,"stroke",d)),h=M7(this,"fontFamily",d),k=M7(this,"fontStyle",d),l=M7(this,"fontVariant",d),m=M7(this,"fontWeight",d),p=M7(this,"fontSize",d),q=this.O()?this.O().Ka():null,r=q&&!q.xf();r&&q.suspend();K7(c.Wh,e);L7(c.Wh,f);c.Wh.Cd("font-family",h);c.Wh.Cd("font-style",k);c.Wh.Cd("font-variant",l);c.Wh.Cd("font-weight",m);c.Wh.Cd("font-size",p);c.Wh.zIndex(d==$.hm?0:1E-6);r&&q.resume();return b}};
$.g.oq=$.ia;$.g.ML=function(a){var b=this.Qi();a=$.A(a)?a.length?a[0]:window.NaN:a;if(b&&b.target()&&!(0,window.isNaN)(a)){var c=b.target().$();c.select(a);a=this.An();c=$.J(a,$.iz)?c.o("category"):c.get(this.Er[1]);$.dO(b,c)}};$.g.gA=function(){var a=this.Qi();a&&a.enabled()&&$.eO(a)};
$.g.Tg=function(a){var b=a.type;switch(b){case "mouseout":b="pointmouseout";break;case "mouseover":b="pointmouseover";break;case "mousemove":b="pointmousemove";break;case "mousedown":b="pointmousedown";break;case "mouseup":b="pointmouseup";break;case "click":b="pointclick";break;case "dblclick":b="pointdblclick";break;default:return null}var c;"pointIndex"in a?c=a.pointIndex:"labelIndex"in a?c=a.labelIndex:"markerIndex"in a&&(c=a.markerIndex);c=$.N(c);a.pointIndex=c;return{type:b,actualTarget:a.target,
series:this,pointIndex:c,target:this,originalEvent:a,point:this.be(c)}};$.g.ig=function(a){a=$.Y.prototype.ig.call(this,a);var b=$.xo(a.domTarget).index;if(!$.n(b)&&$.nx(this.state,$.Ao)){var c=$.tx(this.state,$.Ao);c.length&&(b=c[0])}b=$.N(b);(0,window.isNaN)(b)||(a.pointIndex=b);return a};$.g.tm=function(){};$.g.Ul=function(a){return $.n(a)?(a=$.Bk(a),a!=this.K&&(this.K=a),this):this.K};$.g.ej=function(a){return $.n(a)?(this.gd().selectionMode(a),this):this.gd().g("selectionMode")};
$.g.Ii=function(a,b){if(!this.enabled())return this;var c=this.O()?this.O().Ka():null,d=c&&!c.xf();d&&c.suspend();var e=!(b&&b.shiftKey);$.A(a)?(b||this.ie(),this.state.Jh($.Bo,a,e?$.Ao:void 0)):$.ea(a)&&this.state.Jh($.Bo,a,e?$.Ao:void 0);d&&c.resume();return this};$.g.ie=function(a){if(this.enabled()){var b=this.O()?this.O().Ka():null,c=b&&!b.xf();c&&b.suspend();var d;$.n(a)?d=a:d=this.state.Gc==$.hm?window.NaN:void 0;this.state.Uh($.Bo,d);c&&b.resume()}};
$.g.$i=function(a){if(!this.enabled())return this;var b=this.O()?this.O().Ka():null,c=b&&!b.xf();c&&b.suspend();if($.A(a)){for(var d=$.tx(this.state,$.Ao),e=0;e<d.length;e++)$.Aa(a,d[e])||this.state.Uh($.Ao,d[e]);$.rx(this.state,a)}else $.ea(a)&&(this.Ld(),$.rx(this.state,a));c&&b.resume();return this};
$.g.Ld=function(a){var b;(b=$.nx(this.state,$.Ao))||(b=!!(this.state.ek()&$.Ao));if(b&&this.enabled()){var c=(b=this.O()?this.O().Ka():null)&&!b.xf();c&&b.suspend();var d;$.n(a)?d=a:d=this.state.Gc==$.hm?window.NaN:void 0;this.state.Uh($.Ao,d);c&&b.resume()}};
$.g.data=function(a,b){if($.n(a)){if(a){var c=a.title||a.caption;c&&this.title(c);a.rows&&(a=a.rows)}this.Wf!==a&&(this.Wf=a,$.pd(this.Yc),$.J(a,$.Fr)?this.la=this.Yc=a.Ui():$.J(a,$.Pr)?this.la=this.Yc=a.Yd():this.la=(this.Yc=new $.Pr($.A(a)||$.z(a)?a:null,b)).Yd(),$.L(this.la,this.dd,this),this.B(4352,1));return this}return this.la};$.g.dd=function(){this.B(4352,1)};$.g.SZ=function(a){return $.n(a)?(a=$.A(a)?$.Ha(a):null,this.D!=a&&(this.D=a,this.B(16388,1)),this):this.D};
$.g.scale=function(a){if($.n(a)){if(a=$.lt(this.qa,a,null,3,null,this.yg,this)){var b=this.qa==a;this.qa=a;this.qa.da(b);b||this.B(131072,1)}return this}return this.qa};$.g.yg=function(){this.B(131072,1)};$.g.kd=function(a){if($.n(a)){if(null===a&&this.vb)this.vb=null,this.B(65536,129);else if(a=$.lt(this.vb,a,null,48,null,this.Vp,this)){var b=this.vb==a;this.vb=a;this.vb.da(b);b||($.$N(this.Qi()),this.B(65536,129))}return this}return this.vb};$.g.Vp=function(a){$.X(a,6)&&this.B(65536,129)};
$.g.Qa=function(a){return $.n(a)?(this.ca.N(a),this):this.ca};$.g.lb=function(a){return $.n(a)?(this.za.N(a),this):this.za};$.g.selected=function(a){return $.n(a)?(this.Ea.N(a),this):this.Ea};$.g.Qi=function(a){this.Mb||(this.Mb=new $.ZN,$.W(this,"colorRange",this.Mb),$.L(this.Mb,this.Sz,this),this.B(32772,1));return $.n(a)?(this.Mb.N(a),this):this.Mb};$.g.Sz=function(a){var b=0,c=0;$.X(a,1)&&(b|=32772,c|=1);$.X(a,8)&&(b|=4,c|=8);$.X(a,2)&&(b|=32768,c|=8);this.B(b,c)};
$.g.ds=function(a){return $.yo(this.Qi(),a)};$.g.Ll=function(a){var b,c=[],d;if("categories"==a&&(d=$.J(this.An(),$.iz)?this.An():void 0)){var e=d.qr();a=0;for(b=e.length;a<b;a++){var f=e[a];"default"!==f.name&&c.push({text:f.name,iconEnabled:!0,iconType:"square",iconFill:f.color,disabled:!this.enabled(),sourceUid:$.oa(this),sourceKey:a,meta:{X:this,scale:d,xe:f}})}}return c};$.g.Ls=function(a){return"categories"==a};
$.g.xr=function(a,b){var c=a.o();if("categories"==this.eg().g("itemsSourceMode")){var d=c.X;var e=c.scale;if(e&&d){var f=[];c=c.xe;for(var h=d.Dc();h.advance();){var k=h.get("value"),l=h.o("category");c==e.Cn($.n(l)?l:k)&&f.push(h.ma())}"single"==this.gd().g("hoverMode")?b.fg={X:d,vd:f}:b.fg=[{X:d,vd:f,Kn:f[f.length-1],Ee:{index:f[f.length-1],Sf:0}}]}}};
$.g.vq=function(a,b){var c=a.o();if("categories"==this.eg().g("itemsSourceMode")){var d=c.X;var e=c.scale;if(e&&d){c=c.xe;for(var f=d.Dc(),h=[];f.advance();){var k=f.get("value"),l=f.o("category");c==e.Cn($.n(l)?l:k)&&h.push(f.ma())}if(e=$.xo(b.domTarget))"single"==this.gd().g("hoverMode")?e.fg={X:d,vd:h}:e.fg=[{X:d,vd:h,Kn:h[h.length-1],Ee:{index:h[h.length-1],Sf:0}}];(d=$.zr(this,"colorRange"))&&d.enabled()&&d.target()&&$.dO(d,$.n(c.ep)?c.ep:(c.start+c.end)/2)}}};
$.g.uq=function(a,b){var c=a.o();if("categories"==this.eg().g("itemsSourceMode")){if("single"==this.gd().g("hoverMode")){var d=$.xo(b.domTarget);d&&(d.X=c.X)}(c=$.zr(this,"colorRange"))&&c.enabled()&&c.target()&&$.eO(c)}};$.g.hda=function(a){return[this.f/this.i*(a*=.1)*Math.cos(a),a*Math.sin(a)]};
$.g.getContext=function(a){a.width=a.height=1;var b=Math.sqrt(a.getContext("2d").getImageData(0,0,1,1).data.length>>2);a.width=2048/b;a.height=2048/b;a=a.getContext("2d");a.fillStyle=a.strokeStyle="red";a.textAlign="center";return{context:a,ratio:b}};
$.g.ob=function(){var a=this.qa;if(a){var b,c=this.An();if(this.J(8192)){var d=this.g("anglesCount");var e=this.g("fromAngle");var f=this.g("toAngle");f-=e;this.ba=[];for(b=0;b<d;b++)this.ba.push(e+f/(1==d?d:d-1)*b);this.D||this.B(16388);this.I(8192)}if(this.J(4096)){var h=this.Dc();this.aa=[];this.b&&this.b.forEach(function(a,b){a.Wh.parent(null);a.pl.parent(null);a.pl.zl();this.aa[b]=a},this);this.b=[];this.Zn=[];a.Ag();for(c.Ag();h.advance();){b=String(h.get("x")).toLowerCase();e=(0,window.parseFloat)(h.get("value"));
f=h.get("category");var k=h.ma();var l=this.aa[k]?this.aa[k]:{};l.rowIndex=k;l.text=b;l.value=e;l.UC=!1;l.Xsa=f;this.b.push(l);h.o("item",l);Isa(this)}a.Hg();c.Hg();this.vb||($.Ka(this.Zn,void 0,function(a){return $.C(a)?a.color+" "+a.opacity:a}),Bsa(c,this.Zn));$.Ra(this.b,function(a,b){return b.value-a.value});this.B(16388);this.I(200704)}if(this.J(196608)){this.Zn=[];h=this.Dc();a.Ag();for(c.Ag();h.advance();)Isa(this);c.Hg();this.vb||($.Ka(this.Zn,void 0,function(a){return $.C(a)?a.color+" "+
a.opacity:a}),Bsa(c,this.Zn));this.J(65536)&&this.B(49680);this.J(131072)&&this.B(49156);this.I(196608)}if(this.J(16384)){var m=this.D?this.D:this.ba;var p=Math.max((0,$.za)(m,0),0);d=m.length;a=this.b.length?this.b[0].value:window.NaN;h=this.$();c=this.b.length;var q=0;this.b.forEach(function(a,b){var c=$.fm($.ox(this.state,a.rowIndex));h.select(a.rowIndex);var e=M7(this,"fontFamily",c),f=M7(this,"fontStyle",c),k=M7(this,"fontVariant",c),l=M7(this,"fontWeight",c),r=$.Xb(M7(this,"fill",c));c=$.Zb(M7(this,
"stroke",c));a.font=e;a.style=f;a.variant=k;a.weight=l;a.fill=r;a.stroke=c;a.rotate=m[(b+p+d)%d];q+=a.value},this);this.La("sum",q);this.La("max",a);this.La("min",this.b.length?this.b[c-1].value:window.NaN);this.La("average",q/c);this.La("pointsCount",c);this.I(16384)}}};$.g.ov=function(){this.ob()};
$.g.Qh=function(a){var b=this.scale(),c=$.zr(this,"colorRange");this.J(32768)&&c&&(c.ka(),c.scale(this.An()),c.target(this),c.kb(this),c.da(!1),c.enabled()&&this.B(4));if(this.J(4)){c&&c.enabled()?(c.ja(a.clone().round()),this.j=c.yd()):this.j=a.clone();this.f=this.j.width;this.i=this.j.height;this.$a="spiral"==this.g("mode")?this.hda:Fsa(this);a=this.b.length;var d=this.b[0],e=-1,f=null,h=this.getContext(this.canvas?this.canvas:this.canvas=window.document.createElement("canvas")),k=Gsa((this.f>>
5)*this.i),l=Math.sqrt(this.f*this.f+this.i*this.i);Csa(this,d);for(this.b.forEach(function(a){this.$().select(a.rowIndex);delete a.size;delete a.PE;var c=$.fm($.ox(this.state,a.rowIndex));c=M7(this,"fontSize",c);var d=$.Za(b.transform(a.value),0,1);d=~~(this.P+d*(this.Ja-this.P));a.size=null!=c?$.zo(c)?d*(0,window.parseFloat)(c)/100:c:d},this);++e<a;)d=this.b[e],d.x=this.f>>1,d.y=this.i>>1,Dsa(this,h,d,this.b,e),d.M2&&Hsa(this,k,d,f,l)&&(f?Esa(f,d):f=[{x:d.x+d.Gj,y:d.y+d.ze},{x:d.x+d.li,y:d.y+d.Qe}],
d.x-=this.f>>1,d.y-=this.i>>1);a=f?Math.min(this.f/Math.abs(f[1].x-this.f/2),this.f/Math.abs(f[0].x-this.f/2),this.i/Math.abs(f[1].y-this.i/2),this.i/Math.abs(f[0].y-this.i/2))/2:1;this.wb||(this.wb=this.Oa.Bd());(e=$.zr(this,"background"))&&this.wb.zIndex((e.zIndex()||0)+1);this.G||(this.G=this.wb.Bd(),$.su(this,this.G));this.ye||(this.ye=this.wb.Bd());this.na=this.j.left+(this.f>>1);this.Ca=this.j.top+(this.i>>1);this.Ia=a;this.wb.oc(a,0,0,a,this.na,this.Ca);var m=this.wb.Sd;this.b.forEach(function(a){var b=
[a.x,a.y];m.transform(b,0,b,0,1);if(b[0]+a.Gj<this.j.left||b[0]+a.li>this.j.cb()||b[1]+a.ze<this.j.top||b[1]+a.Qe>this.j.Ua())a.UC&&(a.Wh.parent(null),a.pl.parent(null)),a.UC=!1;else{a.UC||(a.Wh=a.Wh?a.Wh.parent(this.ye):Asa(this.ye),a.Wh.Cd("text-anchor","middle"),a.Wh.Gd(!0),a.Wh.text(a.text.toLowerCase()),a.Wh.cursor("default"),a.pl=a.pl?a.pl.parent(this.G):Asa(this.G),a.pl&&(a.pl.tag={X:this,index:a.rowIndex}),a.pl.Cd("fill","#fff"),a.pl.Cd("opacity",1E-6),a.pl.Cd("text-anchor","middle"),a.pl.text(a.text.toLowerCase()),
a.pl.cursor("default"),a.UC=!0);var c=$.fm($.ox(this.state,a.rowIndex));this.$().select(a.rowIndex);b=$.Xb(M7(this,"fill",c));var d=$.Zb(M7(this,"stroke",c)),e=M7(this,"fontFamily",c),f=M7(this,"fontStyle",c),h=M7(this,"fontVariant",c),k=M7(this,"fontWeight",c);c=M7(this,"fontSize",c);K7(a.Wh,b);L7(a.Wh,d);a.Wh.Cd("font-family",e);a.Wh.Cd("font-style",f);a.Wh.Cd("font-variant",h);a.Wh.Cd("font-weight",k);a.Wh.Cd("font-size",c);a.Wh.Cd("transform","translate("+[a.x,a.y]+")rotate("+a.rotate+")");a.Wh.zIndex(0);
a.pl.Cd("font-family",e);a.pl.Cd("font-style",f);a.pl.Cd("font-variant",h);a.pl.Cd("font-weight",k);a.pl.Cd("font-size",c);a.pl.Cd("transform","translate("+[a.x,a.y]+")rotate("+a.rotate+")");a.pl.zIndex(0)}},this);this.I(16);this.I(4)}this.J(32768)&&(c&&(c.ka(),c.O(this.Oa),c.W(),c.da(!1)),this.I(32768));if(this.J(16)){var p=this.Dc();this.b.forEach(function(a){var b=$.fm($.ox(this.state,a.rowIndex));p.select(a.rowIndex);a.UC&&a.Wh&&(K7(a.Wh,$.Xb(M7(this,"fill",b))),L7(a.Wh,$.Zb(M7(this,"stroke",
b))))},this);this.I(16)}};$.g.iD=function(){return["x"]};$.g.jD=function(a){return a.get("x")};$.g.hD=function(a){a=a.get("name");return $.z(a)?a:null};$.g.fD=function(){return this.data().hd("category")?["value","category"]:["value"]};$.g.yj=function(){return!this.$().Gb()};$.g.Yv=function(a){var b;$.z(a)?(b=$.ft(a,null))||(b=null):$.C(a)?(b=$.ft(a.type,!0),b.N(a)):b=null;return b};$.g.GE=function(a){var b=a.scale;(b=this.Yv(b))&&this.scale(b);b=a.colorScale;(b=this.Yv(b))&&this.kd(b)};
$.g.U=function(a,b){J7.u.U.call(this,a,b);$.Oq(this,N7,a,b);this.GE(a);this.data(a.data);this.SZ(a.angles);this.cc(a.palette);this.Qi().fa(!!b,a.colorRange);this.ca.fa(!!b,a);this.ca.fa(!!b,a.normal);this.za.fa(!!b,a.hovered);this.Ea.fa(!!b,a.selected)};
$.g.F=function(){var a=J7.u.F.call(this);$.Wq(this,N7,a);a.data=this.data().F();$.n(this.D)&&(a.angles=this.D);a.scale=this.scale().F();this.kd()&&(a.colorScale=this.kd().F());a.colorRange=this.Qi().F();a.palette=this.cc().F();a.normal=this.ca.F();a.hovered=this.za.F();a.selected=this.Ea.F();return{chart:a}};
$.g.R=function(){for(var a=0;a<this.b.length;a++){var b=this.b[a];$.pd(b.Wh);$.pd(b.pl);$.pd(b.PE)}$.ud(this.ye,this.G,this.wb,this.ca,this.za,this.Ea,this.Mb,this.state,this.Fa,this.la,this.Yc);this.Fa=this.state=this.qa=this.vb=this.Mb=this.Ea=this.za=this.ca=this.wb=this.G=this.ye=null;delete this.la;this.Yc=null;J7.u.R.call(this)};var O7=J7.prototype;O7.getType=O7.Ma;O7.data=O7.data;O7.angles=O7.SZ;O7.scale=O7.scale;O7.colorScale=O7.kd;O7.colorRange=O7.Qi;O7.palette=O7.cc;O7.normal=O7.Qa;
O7.hovered=O7.lb;O7.selected=O7.selected;O7.hover=O7.$i;O7.unhover=O7.Ld;O7.select=O7.Ii;O7.unselect=O7.ie;O7.getPoint=O7.be;$.Wp["tag-cloud"]=Jsa;$.F("anychart.tagCloud",Jsa);}).call(this,$)}