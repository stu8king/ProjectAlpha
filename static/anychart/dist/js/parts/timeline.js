if(!_.timeline){_.timeline=1;(function($){var h4=function(){$.Y.call(this);this.path=$.rk();$.T(this.ua,[["stroke",0,1]])},i4=function(){$.Y.call(this);this.G=0;this.ye=[];this.j=0;this.i=new $.Gw;$.T(this.ua,[["stroke",16,1],["fill",16,1],["height",276,5]])},j4=function(){this.jd=[]},k4=function(){$.V.call(this);$.T(this.ua,[["length",0,1],["stroke",0,1]])},l4=function(a){$.MA.call(this,a)},m4=function(a,b,c,d,e){$.vB.call(this,a,b,c,d,e);this.f="up";$.T(this.ua,[["direction",2048,1,4294967295]])},n4=function(a,b){return $.n(b)?(a.f=b,a):
a.f},o4=function(a){var b=a.g("direction");return"auto"==b||"odd-even"==b?a.f:b},p4=function(a,b,c,d,e){m4.call(this,a,b,c,d,e)},q4=function(a){$.MA.call(this,a)},r4=function(a,b,c,d,e){m4.call(this,a,b,c,d,e);$.T(this.ua,[["height",0,0]])},s4=function(){$.Mz.call(this);this.Ga("timeline");this.eb=new $.tt;$.W(this,"scale",this.eb);this.eb.uz([[{unit:"minute",count:10},{unit:"hour",count:1},{unit:"day",count:1}],[{unit:"hour",count:4},{unit:"hour",count:12},{unit:"day",count:1}],[{unit:"day",count:1},
{unit:"day",count:2},{unit:"week",count:1}],[{unit:"day",count:2},{unit:"week",count:1},{unit:"month",count:1}],[{unit:"month",count:1},{unit:"quarter",count:1},{unit:"year",count:1}],[{unit:"quarter",count:1},{unit:"year",count:1},{unit:"year",count:10}],[{unit:"year",count:1},{unit:"year",count:10},{unit:"year",count:50}],[{unit:"year",count:10},{unit:"year",count:50},{unit:"year",count:200}]]);this.axis().scale(this.eb);$.L(this.eb,this.ii,this);this.og=[];this.tg=[];this.rg=[];this.wj=this.D=
0;this.P={uC:0,CE:0};this.Za=this.$a=0;this.ea=[];this.fb=[]},Xpa=function(a){a.scale().reset();a.Ia=window.Infinity;a.Ja=-window.Infinity;a.f={dj:0,Lj:a.ec.width,sg:-a.ec.height/2,mg:a.ec.height/2};a.axis().B(400);t4(a,0,0)},u4=function(a){for(var b=a.length-1;0<=b;b--){var c=a[b];$.n(c)&&c.md&&$.Ca(a,b,1)}},v4=function(a){return a.axis().enabled()?a.axis().g("height"):0},t4=function(a,b,c){!$.n(b)||b==a.$a&&c==a.Za||(a.$a=b,a.Za=c,$.qr(a,"timelinechart","scroll",1))},Ypa=function(a,b){var c=a.dj-
b.dj;return 0==c?b.Lj-a.Lj:c},Zpa=function(a,b){var c=a.dj-b.dj;return 0==c?a.Lj-b.Lj:c},w4=function(a,b){a.f.dj=Math.min(a.f.dj,b.dj);a.f.Lj=Math.max(a.f.Lj,b.Lj);a.f.sg=Math.min(a.f.sg,b.sg);a.f.mg=Math.max(a.f.mg,b.mg)},$pa=function(a){var b=new s4;b.Ga("timeline");b.ta("defaultSeriesType","moment");for(var c=0,d=arguments.length;c<d;c++)b.moment(arguments[c]);return b};$.H(h4,$.Y);var aqa={};$.vq(aqa,[$.Z.Wn]);$.U(h4,aqa);
h4.prototype.W=function(){this.path.clear();this.path.stroke(this.g("stroke"));if(!this.yc())return this;this.J(8)&&(this.path.zIndex(this.zIndex()),this.I(8));this.J(2)&&(this.path.parent(this.O()),this.I(2));return this};h4.prototype.gq=function(a,b){if(0!=b.height){var c=$.ip(this.g("stroke"));c=$.R(b.left+a*b.width,c);var d=Math.floor($.R(b.top,1));this.path.moveTo(c,Math.ceil($.R(b.Ua(),1))).lineTo(c,d)}};h4.prototype.remove=function(){this.path&&this.path.parent(null)};
h4.prototype.R=function(){$.ud(this.path);this.path=null;h4.u.R.call(this)};$.H(i4,$.Y);var bqa={};$.vq(bqa,[$.Z.Wn,$.Z.xz,[0,"height",$.Eq]]);$.U(i4,bqa);$.g=i4.prototype;$.g.sa=$.Y.prototype.sa|464;$.g.ra=$.Y.prototype.ra|4;$.g.offset=function(a){return $.n(a)?(this.j!=a&&(this.j=a,this.B(400)),this):this.j};$.g.scale=function(a){return $.n(a)?(a!=this.qa&&(this.qa&&$.nr(this.qa,this.ii,this),this.qa=a,$.L(this.qa,this.ii,this)),this):this.qa};$.g.ii=function(){this.B(400,0)};
$.g.Xa=function(a){this.mb||(this.mb=new h4,$.W(this,"ticks",this.mb),$.L(this.mb,this.ki,this));return $.n(a)?(this.mb.N(a),this):this.mb};$.g.ki=function(){this.B(256,1)};$.g.labels=function(a){this.zj||(this.zj=new $.Ix,$.L(this.zj,this.dI,this),$.W(this,"labels",this.zj));return $.n(a)?(this.zj.N(a),this):this.zj};$.g.dI=function(){this.B(128,1)};
$.g.W=function(){var a=this.scale();this.Rw();if(!a)return $.il(2),this;if(!this.yc())return this;this.Oa||(this.Oa=this.O().Bd(),this.f||(this.f=this.Oa.path(),this.D=this.Oa.path(),this.D.zIndex(37)),this.Oa.hc(this.XT()));this.b||(this.b=new $.bz,this.b.labels(this.labels()),$.dz(this.b),$.wl(this.b),this.b.wa($.OE|$.PE));this.J(2)&&(this.Oa.parent(this.O()),this.I(2));this.J(8)&&(this.Oa.zIndex(this.zIndex()),this.I(8));if(this.J(4)){var b=this.ja();this.G=b.top+b.height/2;b=this.ja();var c=b.left,
d=this.g("height");this.K=new $.I(c,this.G-d/2,b.width,d);this.B(400);this.I(4)}if(this.J(16)){var e=this.ja(),f=this.G;b=this.g("height");var h=b/2;this.f.clear();this.D.clear();c=this.g("stroke");d=this.g("fill");var k=$.ip(c),l=this.scale().uj(),m=this.scale().transform(l.min);l=this.scale().transform(l.max+this.j);m*=e.width;l*=e.width;m+=e.left;e=l+e.left;m=$.R(m,k);e=$.R(e,k);l=$.R(f-h,k);f=$.R(f+h,k);this.Oa.clip(new $.I(Math.floor(m),Math.floor(l),Math.ceil(e)-Math.floor(m),Math.ceil(f)-Math.floor(l)));
0!=b&&(this.f.moveTo(m,l).lineTo(e,l).lineTo(e,f).lineTo(m,f).close(),this.D.moveTo(m,l).lineTo(e,l).lineTo(e,f).lineTo(m,f).close(),this.D.stroke(c),this.f.fill(d),this.f.stroke("none"));this.I(16)}if(this.J(256)){if(b=$.zr(this,"ticks"))for(b.O(this.Oa),b.W(),c=this.En(),d=this.scale().uj(),a.Tj()&&(c.length=1),a=0;a<c.length;a++)f=c[a],h=this.scale().transform(f.start),f.start>=d.min&&b.gq(h,this.K);this.I(256)}this.J(64)&&this.I(64);this.J(128)&&(this.labels().enabled()?(this.Kf.parent(this.Oa),
this.vi()):this.Kf.parent(null),this.I(128));return this};$.g.En=function(){var a,b=this.scale(),c=$.It(b),d=b.sj();for(a=0;a<c.length;a++){var e=b.En(void 0,void 0,c[a].unit,c[a].count,d);if(10>=e.length){4>e.length&&0<a&&(b.En(void 0,void 0,c[a-1].unit,c[a-1].count,d),a--);break}}a==c.length&&a--;e=c[a].unit;a=c[a].count;this.P={unit:e,count:a};d.min+=this.j;d.max+=this.j;return e=b.En(void 0,void 0,e,a,d)};$.g.XT=function(){this.Kf||(this.vl=$.ng().Uo(),this.Kf=$.vk(this.vl));return this.Kf};
$.g.vi=function(){var a=this.En(),b=this.scale(),c=this.ja(),d=this.g("height"),e=b.uj(),f=this.labels(),h=this.P.unit,k=b.Tj();k&&(a.length=1);$.vl.measure();$.ez(this.b);for(var l=0;l<a.length;l++){var m=this.ye[l];m.text(D);m.style(f.flatten());m.Hj();l<a.length-1&&$.Sx(this.ye[l+1]);var p=a[l];if(p.start<e.min)$.Qx(m,null);else{switch(h){case "minute":var q="hour";break;case "hour":q="day";break;case "day":q="month";break;default:q="year"}k&&(h="day",q="year");D=$.ws($.us(h,q,"timeline"));q=c.left+
c.width*b.transform(p.start);for(var r=k?c.left+c.width:c.left+c.width*b.transform(p.end),t=this.labels().padding().Ng(r-q),u,v=!1,w=window.Infinity,x="yyyy/MM/dd'T'HH:mm:ss.SSS",y=0;y<D.length;y++){var B=D[y],G=this.b.pA;if(B in G){G=Math.ceil(G[B].width);if(G<=t){u=B;v=!0;break}G<=w&&(w=G,x=B)}}v||(u=x);var D=this.labels().rk($.qv(this.i,{value:{value:$.xs(p.start,u),type:"string"},tickValue:{value:p.start,type:"number"}}));m.text(D);m.style(f.flatten());m.Hj();t=b.transform(p.start);b.transform(Math.min(p.end,
e.max+this.j));0!=d?$.Qx(m,this.vl):$.Qx(m,null);p=this.labels().padding();v=$.R(c.left+c.width*t,1);w=Math.floor(this.G-d/2);x=d;t=r-q;q=p.Dj(new $.I(v,w,t,x));$.Xx(m,q,this.Oa.Ka())}}for(l=a.length;l<this.ye.length;l++)$.Qx(this.ye[l],null)};$.g.yc=function(){if(this.pf())return!1;if(!this.enabled())return this.J(1)&&(this.remove(),this.I(1),this.B(450)),!1;this.I(1);return!0};$.g.remove=function(){this.Oa&&this.Oa.parent(null)};
$.g.Rw=function(){var a=this.En();if(!this.ye.length)for(var b=0;b<a.length;b++){var c=new $.Jx;this.ye.push(c)}if(this.ye.length<a.length)for(b=this.ye.length;b<a.length;b++)this.ye.push(new $.Jx);return this.ye};$.g.R=function(){$.ud(this.mb,this.f,this.D,this.zj,this.ye);this.zj=this.D=this.f=this.mb=null;this.ye.length=0;i4.u.R.call(this)};var x4=i4.prototype;x4.ticks=x4.Xa;x4.labels=x4.labels;j4.prototype.b=function(a,b){var c=a.dj-b.dj;return 0==c?(c=a.Lj-b.Lj,0==c?-1:c):a.dj-b.dj};j4.prototype.f=function(a,b){return 0==a.sg-b.sg?a.mg-b.mg:a.sg-b.sg};
j4.prototype.add=function(a,b){var c=a.mg-a.sg;a.sg=0;a.mg=c;$.Ua(this.jd,a,this.b);var d=[],e=[],f=!0,h;for(h=0;h<this.jd.length;h++){var k=this.jd[h];if(k!=a){if(k.Lj>a.dj&&f||k.dj<a.Lj&&!f)d.push(k),$.Ua(e,k,this.f)}else f=!1}for(h=0;h<e.length;h++)if(k=e[h],a.sg<=k.mg&&a.sg>=k.sg||a.mg<=k.mg&&a.mg>=k.sg||k.sg<=a.mg&&k.sg>=a.sg||k.mg<=a.mg&&k.mg>=a.sg)b?a.mg=k.mg+c:(a.sg=k.mg,a.mg=a.sg+c)};$.H(k4,$.V);k4.prototype.ra=$.V.prototype.ra|1;var cqa={};$.vq(cqa,[$.Z.Wn,$.Z.aK]);$.U(k4,cqa);$.H(l4,$.MA);$.VG[34]=l4;l4.prototype.type=34;l4.prototype.flags=521;l4.prototype.ug=function(a,b){var c=this.bd,d=a.get(this.X.Ce()[0]);d=this.nh(d,this.prevValue);var e={};e[d.stroke]=!0;a.o("names",d);c=c.ed(b,e)[d.stroke];d=a.o("x");e=a.o("zero");var f=a.o("minLength"),h=$.ip(c.stroke()),k=a.o("axisHeight"),l="up"==(a.get("direction")||a.o("direction"));e+=l?-k/2:k/2;d=$.R(d,h);$.KA(c,this.xa,d,e);$.LA(c,this.xa,d,l?e-f:e+f)};$.H(m4,$.vB);m4.prototype.sa=$.vB.prototype.sa;var y4={};$.vq(y4,[$.Z.bZ]);$.U(m4,y4);$.g=m4.prototype;$.g.ly=function(){return 0};$.g.TN=function(){return!1};$.g.ND=function(a){a=$.Xk(a.Dh());var b=this.ya.Ra().sj();return a>=b.min||a<=b.max?!0:!1};$.g.gh=function(){return!1};$.g.eX=$.ia;
$.g.ST=function(a,b,c){var d=this.data();d.$();this.eX(a,b,c);this.B(512);return this.pd={data:a,X:this,BW:0,I2:this.check($.WG)&&(d.hd("normal")||d.hd("hovered")||d.hd("selected")||d.hd("label")||d.hd("hoverLabel")||d.hd("selectLabel")||d.hd("minLabel")||d.hd("hoverMinLabel")||d.hd("selectMinLabel")||d.hd("maxLabel")||d.hd("hoverMaxLabel")||d.hd("selectMaxLabel")),J2:this.check(4194304)&&(d.hd("normal")||d.hd("hovered")||d.hd("selected")||d.hd("marker")||d.hd("hoverMarker")||d.hd("selectMarker")),
K2:this.check(256)&&(d.hd("outliers")||d.hd("normal")||d.hd("hovered")||d.hd("selected")||d.hd("outlierMarker")||d.hd("hoverOutlierMarker")||d.hd("selectOutlierMarker")),QU:!1,L2:!1,H2:!1}};$.g.nI=function(a){var b=this.g("direction");if("auto"==b||"odd-even"==b)b=n4(this);a.o("direction",b);b=this.ja();a.o("zero",b.top+b.height/2)};$.g.TI=function(){this.Uj.push(this.nI)};$.g.F=function(){var a=m4.u.F.call(this);$.Wq(this,y4,a);return a};$.g.U=function(a,b){m4.u.U.call(this,a,b);$.Oq(this,y4,a,b)};$.H(p4,m4);$.g=p4.prototype;$.g.nI=function(a,b,c,d,e){p4.u.nI.call(this,a,b,c,d,e);b=this.ja();c=this.Yf().g("length");a.o("length",$.M(c,b.height));a.o("x",b.left+b.width*e)};$.g.RA=function(a,b,c){var d=this.rl().transform(a.Dh());a.o("xRatio",d);for(var e=0;e<this.Uj.length;e++)this.Uj[e].call(this,a,b,c,0,d)};$.g.Yf=function(a){this.b||(this.b=new k4,this.b.kb(this),$.L(this.b,this.HC,this),$.W(this,"connector",this.b));return $.n(a)?(this.b.N(a),this):this.b};$.g.HC=function(){this.B(2048,1)};
$.g.eX=function(a,b,c){for(var d=this.data().$();d.advance();){var e=c(d.get("x")),f={},h={};f.x=e;h.rawIndex=d.ma();b(a,{data:f,o:h})}};$.g.Ip=function(){var a=this.$(),b=a.o("minLength"),c=this.ja();c=c.top+c.height/2;var d="up"==(a.get("direction")||o4(this));a=a.o("axisHeight")/2;return d?c-b-a:c+b+a};$.g.wE=function(){return"up"==(this.$().get("direction")||o4(this))?"center-bottom":"center-top"};
$.g.vm=function(a,b){var c=p4.u.vm.call(this,a,b);c.date={value:$.ss(b.get("x")),type:"date-time"};return c};$.g.R=function(){this.b&&($.nr(this.b,this.HC,this),$.ud(this.b),this.b=null);p4.u.R.call(this)};$.H(q4,$.MA);$.VG[35]=q4;q4.prototype.type=35;q4.prototype.flags=1537;
q4.prototype.ug=function(a,b){var c=this.bd,d=a.get(this.X.Ce()[0]);d=this.nh(d,this.prevValue);var e={};e[d.path]=!0;a.o("names",d);c=c.ed(b,e)[d.path];d=a.o("startX");e=a.o("endX");var f=a.o("zero"),h=a.o("axisHeight");a.o("stackLevel");var k=a.get("direction")||a.o("direction"),l=a.o("startY"),m=a.o("endY");"up"==k?(f-=h/2,h=f-l-m):(f+=h/2,h=f+l+m);k=$.ip(c.stroke());d=$.R(d,k);e=$.R(e,k);c.moveTo(d,f).lineTo(d,h).lineTo(e,h).lineTo(e,f).close()};$.H(r4,m4);var dqa={};$.vq(dqa,[$.Z.$J]);$.U(r4,dqa);$.g=r4.prototype;$.g.RA=function(a,b,c){var d=this.rl(),e=d.transform(a.get("start"));d=d.transform(a.get("end"));a.o("startXRatio",e);a.o("endXRatio",d);for(e=0;e<this.Uj.length;e++)this.Uj[e].call(this,a,b,c,0)};
$.g.nI=function(a,b,c,d,e){r4.u.nI.call(this,a,b,c,d,e);b=this.ja();c=a.o("startXRatio");c=b.left+b.width*c;d=a.o("endXRatio");if(!$.ea(d)||(0,window.isNaN)(d))d=this.rl(),e=d.uj().max,d=d.transform(e);d=b.left+b.width*d;a.o("startX",c);a.o("endX",d);b=$.M(this.g("height"),b.height);a.o("height",b)};$.g.eX=function(a,b,c){for(var d=this.data().$();d.advance();){var e=c(d.get("start")),f=c(d.get("end")),h={},k={};h.start=e;h.end=f;k.rawIndex=d.ma();b(a,{data:h,o:k})}};
$.g.bi=function(){var a=this.$(),b=a.o("height");var c=a.o("zero");var d=a.o("axisHeight");var e=a.o("startX");var f=a.o("endY");a="up"==(a.get("direction")||o4(this));d/=2;b=f-b/2;c=c+(a?-d:d)+(a?-b:b);a=this.ya.ec.clone().left+this.ya.wj;a>e&&(e=a);return{value:{x:e||0,y:c||0}}};$.g.vm=function(a,b){var c=r4.u.vm.call(this,a,b);c.start={value:$.ss(b.get("start")),type:"date-time"};c.end={value:$.ss(b.get("end")),type:"date-time"};return c};
$.g.M_=function(a,b){var c=this.bg();c.select(b);var d=c.o("startX"),e=this.ya.ec.clone().left+this.ya.wj;e>d&&(d=e);e=c.o("endX");c=c.o("height");a.width(e-d);a.height(c)};$.H(s4,$.Mz);var z4={},eqa=$.WG|1572864;z4.moment={Fb:34,Kb:2,Lb:[$.tH],Ob:null,Jb:null,Cb:eqa|4194304,zb:"zero"};z4.range={Fb:35,Kb:2,Lb:[$.WH],Ob:null,Jb:null,Cb:eqa,zb:"zero"};s4.prototype.fj=z4;$.Nz(s4,s4.prototype.fj);s4.prototype.sa=$.Mz.prototype.sa|543227904;s4.prototype.ra=$.Cx.prototype.ra;$.Jz(s4,"timelinechart",["scroll"]);$.g=s4.prototype;
$.g.fn=function(a,b){var c=$.N(a);if((0,window.isNaN)(c)){c=0;var d=a}else c=a,d=b;var e=this.rg[c];if(!e){e=new $.fA;$.n(!0)&&(e.i=!0);var f=$.wr($.vr(this),"defaultRangeMarkerSettings");e.Ga(f);e.pa=this;$.gA(e,"vertical");this.rg[c]=e;e.kb(this);$.L(e,this.FK,this);$.od(e,this.JN,this);this.B(4194304,1)}return $.n(d)?(e.N(d),this):e};
$.g.ln=function(a,b){var c=$.N(a);if((0,window.isNaN)(c)){c=0;var d=a}else c=a,d=b;var e=this.tg[c];if(!e){e=new $.iA;var f=e;$.n(!0)&&(f.G=!0);f=$.wr($.vr(this),"defaultTextMarkerSettings");e.Ga(f);e.pa=this;$.$y(e,"vertical");this.tg[c]=e;e.kb(this);$.L(e,this.FK,this);$.od(e,this.JN,this);this.B(4194304,1)}return $.n(d)?(e.N(d),this):e};
$.g.Xm=function(a,b){var c=$.N(a);if((0,window.isNaN)(c)){c=0;var d=a}else c=a,d=b;var e=this.og[c];if(!e){e=new $.cA;$.n(!0)&&(e.i=!0);var f=$.wr($.vr(this),"defaultLineMarkerSettings");e.Ga(f);e.pa=this;$.dA(e,"vertical");this.og[c]=e;e.kb(this);$.L(e,this.FK,this);$.od(e,this.JN,this);this.B(4194304,1)}return $.n(d)?(e.N(d),this):e};$.g.FK=function(a){var b=4194304;$.X(a,4)&&(b|=65536);this.B(b,1)};$.g.JN=function(){this.B(65536,1)};
$.g.D6=function(a){if(!this.j){this.j=new $.cA;$.n(!0)&&(this.j.i=!0);var b=$.wr($.vr(this),"defaultLineMarkerSettings");this.j.Ga(b);$.W(this,"todayMarker",this.j);this.j.pa=this;$.dA(this.j,"vertical");this.j.kb(this);$.L(this.j,this.FK,this);$.od(this.j,this.JN,this);b=new Date;this.j.value(Date.UTC(b.getUTCFullYear(),b.getUTCMonth(),b.getUTCDay()));this.B(4259840,1)}return $.n(a)?(this.j.N(a),this):this.j};
$.g.Qh=function(a){if(!this.pf()){this.G||(this.G=this.Oa.Bd(),this.G.zIndex(1),this.vc.De(this,"chartdraw",this.Jga));this.K||(this.K=this.Oa.Bd(),this.K.zIndex(.5));this.ba||(this.ba=this.Oa.Bd(),this.ba.zIndex(1));this.J(4)&&(this.ec=a.clone(),this.B(543195136),$.qr(this,"timelinechart","scroll"),this.I(4));this.Ye=[];this.Ub=[];this.sb=[];var b=v4(this);if(0==this.tj())Xpa(this),this.fb.length=0,this.ea.length=0;else if(this.J(98304)){this.fb=[];this.ea=[];for(var c=window.Infinity,d=-window.Infinity,
e=0,f=0,h=["up","down"],k=0;k<this.hb.length;k++){var l=this.hb[k],m=l.jk();switch(l.g("direction")){case "odd-even":"range"==m?(n4(l,h[e&1]),e++):"moment"==m&&(n4(l,h[f&1]),f++);break;case "auto":"range"==m?n4(l,"up"):"moment"==m&&n4(l,"up")}switch(m){case "moment":this.fb.push(l);break;case "range":this.ea.push(l)}var p=$.wB(l,!1,!0),q=l,r=window.Infinity,t=-window.Infinity,u=q.Dc(),v=q.jk();if("moment"==v)for(;u.advance();){var w=$.Xk(u.get("x"));r=Math.min(r,w);t=Math.max(t,w)}else if("range"==
v)for(;u.advance();){var x=$.Xk(u.get("start")),y=$.Xk(u.get("end"));(0,window.isNaN)(x)||((0,window.isNaN)(y)||(r=Math.min(r,y),t=Math.max(t,y)),r=Math.min(r,x),t=Math.max(t,x))}var B=r;var G=t;c=Math.min(c,B);d=Math.max(d,G);this.Ye.push(p);"range"==m?this.Ub.push(p):this.sb.push(p)}var D=c;var K=d;var O=D;var Q=K;if(-window.Infinity===Q&&window.Infinity===O)Xpa(this);else{u4(this.og);u4(this.rg);u4(this.tg);this.j&&this.j.md&&(this.j=void 0);for(var S=$.Ga(this.og,this.rg,this.tg,[this.j]),wa=
[],sa=0;sa<S.length;sa++){var Qa=S[sa];if(Qa&&Qa.enabled()&&"consider"==Qa.g("scaleRangeMode"))for(var wb=Qa.ws(),pc=0;pc<wb.length;pc++)wa.push($.ss(wb[pc]).getTime())}var hb=Math.min.apply(null,wa),Rb=Math.max.apply(null,wa);O=Math.min(O,hb);Q=Math.max(Q,Rb);if(O==Q){var Kb=$.wp("day",1);O-=Kb/2;Q+=Kb/2}if(this.Ja!=O||this.Ia!=Q)this.Ja=O,this.Ia=Q,$.vt(this.scale(),this.Ja,this.Ia),this.eb.HI?(this.eb.kj.apply(this.eb,this.eb.EI),this.eb.HI=!1,this.eb.EI=null):(this.scale().ka(),this.scale().Pm(),
this.scale().da(!1));for(var Sb=this.Ye,xe,Tb,lc,Eb,rd,rf=[],Nd=[],mc=[],zg=[],gf=[],$h=[],kh=[],Yi=0;Yi<Sb.length;Yi++){rd=Sb[Yi];Eb=rd.X;var Gd=Eb.jk();if("range"==Gd){for(var Od,Jc,nc,Dd=rd,Ag=Dd.X,vc=Dd.data,gg=[],Le=[],zh=[],Pd=v4(this),Qd=this.scale().uj().max,ye=Ag.Dc(),Lf=0;Lf<vc.length;Lf++){ye.select(Lf);var Hk=vc[Lf],sm=ye.get("start"),sd=ye.get("name")||ye.get("x");if(null==sm||(0,window.isNaN)(sm)||null==sd)ye.o("missing",!0);else{nc=this.scale().transform(Hk.data.start)*this.ec.width;
Jc=(0,window.isNaN)(Hk.data.end)?this.scale().transform(Qd)*this.ec.width:this.scale().transform(Hk.data.end)*this.ec.width;Od=$.M(Ag.g("height"),this.ec.height);var $i=ye.get("direction")||o4(Ag),zi={dj:nc,Lj:Jc,sg:0,mg:Od,direction:$i,X:Ag,QI:Lf,pd:Dd};gg.push(zi);"up"==$i?Le.push(zi):zh.push(zi);Hk.o.axisHeight=Pd}}xe=gg;Tb=Le;lc=zh;rf=$.Ga(rf,xe);Nd=$.Ga(Nd,xe);mc=$.Ga(mc,Tb);zg=$.Ga(zg,lc)}else if("moment"==Gd){var Qg=rd,aj=Qg.X,Me=Qg.data,lh=[],Mj=[],mh=[],Ai=v4(this),Mf=aj.labels();$.Zu(Mf);
for(var Gn=aj.Db(),Ik=Gn.enabled()?Gn.g("size"):0,bj=aj.$(),nh=0;nh<Me.length;nh++)if(bj.select(nh),null!=bj.get("value")&&null!=bj.get("x")){var Bi=Mf.ae(nh),Nj=$.tB(aj,new $.Gw);null===Bi?Bi=Mf.add(Nj,{value:{x:0,y:0}},nh):Bi.Gf(Nj);Bi.b=null;var Jk=Mf.measure(Bi),Ah=Mf.g("offsetX")||0,cj=Me[nh];var Rg=this.scale().transform(cj.data.x)*this.ec.width-Ik;var jf=Rg+Jk.width+Ah+Ik;var dj=50-Jk.height/2;var bi=50+Jk.height/2;var wf=bj.get("direction")||o4(aj),$d={dj:Rg,Lj:jf,sg:dj,mg:bi,direction:wf,
X:aj,QI:nh,pd:Qg};lh.push($d);"up"==wf?Mj.push($d):mh.push($d);cj.o.axisHeight=Ai}else bj.o("missing",!0);xe=lh;Tb=Mj;lc=mh;rf=$.Ga(rf,xe);gf=$.Ga(gf,xe);$h=$.Ga($h,Tb);kh=$.Ga(kh,lc)}}var Rd=mc;var td=zg;var Sg=$h;var Nf=kh;$.Pa(Rd,Ypa);$.Pa(td,Ypa);$.Pa(Sg,Zpa);$.Pa(Nf,Zpa);var Cl=this.scale().uj();this.f={dj:window.Infinity,Lj:-window.Infinity,sg:window.Infinity,mg:-window.Infinity};this.f.dj=Math.min(this.f.dj,this.scale().transform(Cl.min)*this.ec.width);this.f.Lj=Math.max(this.f.Lj,this.scale().transform(Cl.max)*
this.ec.width);var Ub,ze,ci=[],Ci=new j4;for(ze=0;ze<Rd.length;ze++){(Ub=Rd[ze])&&-1==ci.indexOf(Ub.X)&&(Ub.X.zIndex(34-ci.length/100),ci.push(Ub.X));var Sd=Ub.QI;var ae=Ub.pd.data[Sd];Ci.add(Ub,!0);w4(this,Ub);ae.o.startY=Ub.sg;ae.o.endY=Ub.mg;ae.o.stateZIndex=1-Ub.mg/1E6}for(ze=Sg.length-1;0<=ze;ze--)Ub=Sg[ze],Sd=Ub.QI,Ci.add(Ub),w4(this,Ub),ae=Ub.pd.data[Sd],ae.o.minLength=Ub.sg+(Ub.mg-Ub.sg)/2;var ej=new j4;ci=[];for(ze=0;ze<td.length;ze++)(Ub=td[ze])&&-1==ci.indexOf(Ub.X)&&(Ub.X.zIndex(34-ci.length/
100),ci.push(Ub.X)),Sd=Ub.QI,ae=Ub.pd.data[Sd],ej.add(Ub,!0),ae.o.startY=Ub.sg,ae.o.endY=Ub.mg,ae.o.stateZIndex=1-Ub.mg/1E6,w4(this,{dj:Ub.dj,Lj:Ub.Lj,sg:-Ub.mg,mg:-Ub.sg});for(ze=Nf.length-1;0<=ze;ze--)Ub=Nf[ze],Sd=Ub.QI,ej.add(Ub),ae=Ub.pd.data[Sd],ae.o.minLength=Ub.sg+(Ub.mg-Ub.sg)/2,w4(this,{dj:Ub.dj,Lj:Ub.Lj,sg:-Ub.mg,mg:-Ub.sg});var Di=b/2;this.f.sg-=Di;this.f.mg+=Di;var Eg=$.zr(this,"scroller"),di=0,Fg=0;if(Eg&&Eg.enabled()){var xf=Eg.g("orientation");var fj=Eg.g("height");switch(xf){case "top":di=
fj;break;case "bottom":Fg=fj}}var Dl=this.ec.height/2,gv=Dl-Math.abs(this.f.sg)-Fg,tm=this.f.mg-Dl-di;if(this.f.mg-this.f.sg<=this.ec.height){var Is=Sg.length+Rd.length,Kq=Nf.length+td.length;Is&&!Kq?t4(this,gv,gv):!Is&&Kq?t4(this,tm,tm):Is&&Kq&&t4(this,0,0)}else t4(this,gv,tm)}}var Hn=$.zr(this,"scroller"),um=$.zr(this,"axis");this.J(536870912)&&(Hn&&(Hn.O(this.Oa),Hn.ja(this.ec),Hn.W()),this.I(536870912));if($.ur(this,"timelinechart","scroll")){var vm=this.G.ip(),ay=this.P,Oj=ay.uC,XB=ay.CE,oh=
Oj*(this.ec.height-this.axis().height());.5==Math.abs(Oj)&&(oh+=XB);this.D=oh;this.f&&this.wj+this.ec.cb()>this.f.Lj+this.ec.left?this.wj=this.f.Lj-this.ec.cb()+this.ec.left:this.f&&this.wj+this.ec.tb()<this.f.dj+this.ec.left&&(this.wj=this.f.dj-this.ec.tb()+this.ec.left);this.D=$.Za(this.D,this.$a,this.Za);vm[4]=-this.wj;vm[5]=this.D;this.G.oc.apply(this.G,vm);var Ae=this.ec.clone();Ae.left+=this.wj;Ae.top-=this.D;this.G.clip(Ae);vm[5]=0;this.K.oc.apply(this.K,vm);Ae.top=this.ec.top;this.K.clip(Ae);
var hv=this.D,Lq=0;um&&(Lq=um.g("height")/2);var In=0,iv=0;if(Hn&&Hn.enabled()){var Mq=Hn.g("height");var YB=Hn.g("orientation");"top"==YB?In=Mq:"bottom"==YB&&(iv=Mq)}Ae=this.ec.clone();Ae.left+=this.wj;this.D>this.ec.height/2-Lq-iv?hv=this.ec.height/2-Lq-iv:this.D<-(this.ec.height/2)+Lq+In&&(hv=-(this.ec.height/2)+Lq+In);vm[5]=hv;this.ba.oc.apply(this.ba,vm);this.ba.clip(Ae);for(var gj=0;gj<this.ea.length;gj++){var El=this.ea[gj];El.B(256);El.ja(this.ec);El.O(this.G);El.W()}$.sr(this,"timelinechart",
"scroll")}this.J(65536)&&(this.B(6324224),this.I(65536));if(this.J(32768)){for(gj=0;gj<this.hb.length;gj++)El=this.hb[gj],El.ja(this.ec),El.O(this.G),El.W();this.I(32768)}this.J(2097152)&&(um&&(um.ja(this.ec),um.O(this.ba),um.W()),this.I(2097152));if(this.J(4194304)){var kG=$.Ga(this.og,this.rg,this.tg,[this.j]);for(gj=0;gj<kG.length;gj++){var Jn=kG[gj];Jn&&(Jn.B(4),Jn.ka(),Jn.scale()||Jn.OK(this.eb),Jn.ja(this.ec),Jn.O(this.K),Jn.W(),Jn.da(!1))}this.I(4194304)}}};
$.g.H_=function(a){var b=this.scale().sj(),c=this.scale().uj(),d=a.deltaY;$.VC&&(d*=15);if(!a.shiftKey&&this.gd().g("zoomOnMouseWheel")){a.preventDefault();var e=0>a.deltaY;if(b.min<=c.min&&b.max>=c.max&&!e)return;b=a.clientX;this.scale().Lc((b+this.wj)/this.ec.width);this.scale().Lc(this.wj/this.ec.width);this.scale().Lc((this.wj+this.ec.width)/this.ec.width);this.ka();b=(b-this.ec.left)/this.ec.width;e?this.Sr(1.2,b):this.Tr(1.2,b);this.da(!0)}this.gd().g("scrollOnMouseWheel")&&(a.preventDefault(),
this.move(0,d))};$.g.move=function(a,b){this.moveTo(this.wj+a,this.D-b)};
$.g.moveTo=function(a,b){var c=this.scale().sj(),d=this.scale().uj(),e=a-this.wj,f=b-this.D;if(this.G){this.wj=a;this.D=b;0!=e&&(this.wj+this.ec.cb()>this.f.Lj+this.ec.left?this.wj=this.f.Lj-this.ec.cb()+this.ec.left:this.wj+this.ec.tb()<this.f.dj+this.ec.left&&(this.wj=this.f.dj-this.ec.tb()+this.ec.left));0!=f&&(this.D=$.Za(b,this.$a,this.Za));e=this.ec.height-v4(this);f=this.D/e;var h=$.Za(f,-.5,.5);this.P.uC=h;this.P.CE=(f-h)*e;e=this.scale().Lc(this.wj/this.ec.width);f=this.scale().Lc((this.wj+
this.ec.width)/this.ec.width);c=e-c.min;h=d.max-d.min;$.GB(this.I_(),(e-d.min)/h,(f-d.min)/h);this.ka();this.B(2097152);this.axis().offset(c);$.qr(this,"timelinechart","scroll",1);this.da(!0)}};$.g.Jga=function(){this.aa||(this.aa=new $.Fx(this.O().Ka().Ql(),!1),this.aa.va("mousewheel",this.H_,!1,this));this.Oa.va("mousedown",this.X3,!0,this)};
$.g.X3=function(a){var b=this.ec,c=$.zr(this,"scroller");c&&c.enabled()&&(b=c.yd());c=$.ak(this.O().Ka());b&&a.clientX>=b.left+c.x&&a.clientX<=b.left+c.x+b.width&&a.clientY>=b.top+c.y&&a.clientY<=b.top+c.y+b.height&&(this.na=a.clientX,this.Ca=a.clientY,this.Oa.va("mousemove",this.WA,!0,this),$.Ld($.Op,"mouseup",this.XA,!0,this))};$.g.WA=function(a){this.move(this.na-a.clientX,this.Ca-a.clientY);this.na=a.clientX;this.Ca=a.clientY};
$.g.XA=function(){this.Oa.fc("mousemove",this.WA,!0,this);$.Zd(window.document,"mouseup",this.XA,!0,this)};$.g.axis=function(a){this.b||(this.b=new i4,$.L(this.b,this.G_,this),$.wl(this.b),$.W(this,"axis",this.b));return $.n(a)?(this.b.N(a),this):this.b};$.g.Ra=function(){return this.scale()};$.g.G_=function(a){var b=2097152;$.X(a,32772)&&(b|=32772);this.B(b,1)};$.g.scale=function(a){return $.n(a)?(this.eb.N(a),this):this.eb};
$.g.ii=function(a){$.X(a,4)&&(a=this.scale(),a.uj(),a.sj(),this.moveTo(0,this.D),this.B(2162688,1))};$.g.Ft=function(a,b){return"moment"==a?new p4(this,this,a,b,!0):new r4(this,this,a,b,!0)};$.g.vy=function(){return null};$.g.ty=function(){return null};$.g.bb=function(){this.Fc||(this.Fc=new $.Nt);return this.Fc};$.g.xa=function(){return!1};
$.g.kj=function(a,b){this.ka();var c=$.Xk(a),d=$.Xk(b);this.scale().kj(c,d);var e=$.zr(this,"scroller");if(e){var f=this.scale().uj(),h=f.max-f.min;$.GB(e,(c-f.min)/h,(d-f.min)/h)}this.da(!0);return this};$.g.Pm=function(){this.ka();this.scroll(0);this.scale().Pm();this.B(65536,1);this.da(!0);return this};$.g.scroll=function(a){return $.n(a)&&(a=+a,this.D!=a)?(this.moveTo(this.wj,a),this):this.D};
$.g.FY=function(a){if($.n(a)){var b=$.n(a.uC)?$.Za(a.uC,-.5,.5):0;a=$.n(a.CE)&&.5==Math.abs(b)?a.CE:0;if(this.P.uC!==b||this.P.CE!==a)this.P={uC:b,CE:a},$.qr(this,"timelinechart","scroll");return this}return this.P};$.g.Ma=function(){return"timeline"};
$.g.I_=function(a){this.i||(this.i=new $.RB,this.i.kb(this),$.L(this.i,this.Lca,this),this.vc.va(this.i,"scrollerchange",this.J_),this.vc.va(this.i,"scrollerchangefinish",this.J_),$.W(this,"scroller",this.i),this.B(536870916,1));return $.n(a)?(this.i.N(a),this):this.i};$.g.Lca=function(a){var b=536870912,c=1;$.X(a,8)&&(b|=4,c|=8);this.B(b,c)};$.g.J_=function(a){var b=this.scale().uj(),c=b.max-b.min;this.kj(b.min+a.startRatio*c,b.min+a.endRatio*c)};$.g.Ch=function(){return this};
$.g.Sr=function(a,b){var c=this.scale(),d=c.sj(),e=$.n(b)?b:.5,f=c.uj().max-c.uj().min,h=c.Lc(this.wj/this.ec.width);d={min:h,max:h+(d.max-d.min)};h=d.max-d.min;if(2E-4>h/f)return this;h=Math.round(h*((a?1/a:.625)-1));f=d.min-h*e;h=d.max+h*(1-e);6E4>=Math.abs(f-h)&&(d=(d.min+d.max)/2,f=d-6E4*e,h=d+6E4*(1-e));c.kj(f,h);return this};
$.g.Tr=function(a,b){a=a||1.6;var c=this.scale(),d=c.sj(),e=$.n(b)?b:.5,f=c.Lc(this.wj/this.ec.width);d={min:f,max:f+(d.max-d.min)};f=Math.round((d.max-d.min)*(a-1));c.kj(d.min-f*e,d.max+f*(1-e));return this};
$.g.U=function(a,b){s4.u.U.call(this,a,b);a.scale&&(this.scale(a.scale),this.Ja=a.scale.dataMinimum,this.Ia=a.scale.dataMaximum);a.axis&&this.axis(a.axis);this.FY(a.verticalRelativeOffset);this.Kg(a.lineAxesMarkers,this.Xm);this.Kg(a.textAxesMarkers,this.ln);this.Kg(a.rangeAxesMarkers,this.fn);a.todayMarker&&this.D6(a.todayMarker);this.cP(a)};$.g.cP=function(a){var b=a.series;if($.A(b))for(var c=0;c<b.length;c++){a=b[c];var d=a.seriesType||this.g("defaultSeriesType");(d=this.Ae(d,a))&&d.N(a)}};
$.g.Kg=function(a,b){for(var c=0;c<a.length;c++)b.call(this,c).N(a[c])};
$.g.F=function(){var a=s4.u.F.call(this);a.scale=this.scale().F();a.axis=this.axis().F();var b;a.lineAxesMarkers=[];for(b=0;b<this.og.length;b++)a.lineAxesMarkers.push(this.og[b].F());a.textAxesMarkers=[];for(b=0;b<this.tg.length;b++)a.textAxesMarkers.push(this.tg[b].F());a.rangeAxesMarkers=[];for(b=0;b<this.rg.length;b++)a.rangeAxesMarkers.push(this.rg[b].F());$.n(this.j)&&(a.todayMarker=this.j.F());this.XO(a);a.type=this.Ma();a.verticalRelativeOffset=this.FY();return{chart:a}};
$.g.XO=function(a){var b,c=[];for(b=0;b<this.hb.length;b++){var d=this.hb[b].F();c.push(d)}c.length&&(a.series=c)};$.g.afa=function(){var a=this.l2();this.scale().Gr(a.min,a.max);return this};$.g.l2=function(){var a=this.scale(),b=a.sj();a=a.Lc(this.wj/this.ec.width);return{min:a,max:a+(b.max-b.min)}};
$.g.R=function(){$.nr(this.eb,this.ii,this);$.nr(this.b,this.G_,this);this.Oa.fc("mousedown",this.X3,!0,this);this.Oa.fc("mousemove",this.WA,!0,this);$.Zd($.Op,"mouseup",this.XA,!0,this);this.aa.fc("mousewheel",this.H_,!1,this);$.ud(this.b,this.eb,this.Fc,this.og,this.tg,this.rg,this.G,this.j,this.K);this.Fc=this.eb=this.b=null;this.og.length=0;this.tg.length=0;this.rg.length=0;this.K=this.G=this.j=null;s4.u.R.call(this)};var A4=s4.prototype;A4.axis=A4.axis;A4.scale=A4.scale;A4.fitAll=A4.Pm;
A4.fit=A4.Pm;A4.zoomTo=A4.kj;A4.getType=A4.Ma;A4.getCurrentScene=A4.Ch;A4.zoomIn=A4.Sr;A4.zoomOut=A4.Tr;A4.getSeries=A4.ff;A4.addSeries=A4.jl;A4.getSeriesAt=A4.zi;A4.getSeriesCount=A4.tj;A4.removeSeries=A4.xo;A4.removeSeriesAt=A4.Qn;A4.removeAllSeries=A4.Cp;A4.scroll=A4.scroll;A4.lineMarker=A4.Xm;A4.textMarker=A4.ln;A4.rangeMarker=A4.fn;A4.todayMarker=A4.D6;A4.scroller=A4.I_;A4.forceScaleUpdate=A4.afa;A4.getVisibleRange=A4.l2;A4.verticalRelativeOffset=A4.FY;$.Wp.timeline=$pa;$.F("anychart.timeline",$pa);}).call(this,$)}
