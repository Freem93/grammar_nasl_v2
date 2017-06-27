#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(51069);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2015/04/09 13:37:53 $");

  script_cve_id("CVE-2011-1290", "CVE-2011-1291", "CVE-2011-1292", "CVE-2011-1293", "CVE-2011-1294", "CVE-2011-1295", "CVE-2011-1296", "CVE-2011-1301", "CVE-2011-1302", "CVE-2011-1303", "CVE-2011-1304", "CVE-2011-1305", "CVE-2011-1434", "CVE-2011-1435", "CVE-2011-1436", "CVE-2011-1437", "CVE-2011-1438", "CVE-2011-1439", "CVE-2011-1440", "CVE-2011-1441", "CVE-2011-1442", "CVE-2011-1443", "CVE-2011-1444", "CVE-2011-1445", "CVE-2011-1446", "CVE-2011-1447", "CVE-2011-1448", "CVE-2011-1449", "CVE-2011-1450", "CVE-2011-1451", "CVE-2011-1452", "CVE-2011-1454", "CVE-2011-1455", "CVE-2011-1456", "CVE-2011-1799", "CVE-2011-1800", "CVE-2011-1801", "CVE-2011-1804", "CVE-2011-1806", "CVE-2011-1807", "CVE-2011-1808", "CVE-2011-1809", "CVE-2011-1810", "CVE-2011-1811", "CVE-2011-1812", "CVE-2011-1813", "CVE-2011-1814", "CVE-2011-1815", "CVE-2011-1816", "CVE-2011-1817", "CVE-2011-1818", "CVE-2011-1819", "CVE-2011-2332", "CVE-2011-2342", "CVE-2011-2345", "CVE-2011-2346", "CVE-2011-2347", "CVE-2011-2348", "CVE-2011-2349", "CVE-2011-2350", "CVE-2011-2351", "CVE-2011-2358", "CVE-2011-2359", "CVE-2011-2360", "CVE-2011-2361", "CVE-2011-2782", "CVE-2011-2783", "CVE-2011-2784", "CVE-2011-2785", "CVE-2011-2786", "CVE-2011-2787", "CVE-2011-2788", "CVE-2011-2789", "CVE-2011-2790", "CVE-2011-2791", "CVE-2011-2792", "CVE-2011-2793", "CVE-2011-2794", "CVE-2011-2795", "CVE-2011-2796", "CVE-2011-2797", "CVE-2011-2798", "CVE-2011-2799", "CVE-2011-2800", "CVE-2011-2801", "CVE-2011-2802", "CVE-2011-2803", "CVE-2011-2804", "CVE-2011-2805", "CVE-2011-2818", "CVE-2011-2819", "CVE-2011-2821", "CVE-2011-2823", "CVE-2011-2824", "CVE-2011-2825", "CVE-2011-2826", "CVE-2011-2827", "CVE-2011-2828", "CVE-2011-2829", "CVE-2011-2834", "CVE-2011-2835", "CVE-2011-2836", "CVE-2011-2837", "CVE-2011-2838", "CVE-2011-2839", "CVE-2011-2840", "CVE-2011-2841", "CVE-2011-2842", "CVE-2011-2843", "CVE-2011-2844", "CVE-2011-2845", "CVE-2011-2846", "CVE-2011-2847", "CVE-2011-2848", "CVE-2011-2849", "CVE-2011-2850", "CVE-2011-2851", "CVE-2011-2852", "CVE-2011-2853", "CVE-2011-2854", "CVE-2011-2855", "CVE-2011-2856", "CVE-2011-2857", "CVE-2011-2858", "CVE-2011-2859", "CVE-2011-2860", "CVE-2011-2861", "CVE-2011-2862", "CVE-2011-2864", "CVE-2011-2874", "CVE-2011-2875", "CVE-2011-2876", "CVE-2011-2877", "CVE-2011-2878", "CVE-2011-2879", "CVE-2011-2880", "CVE-2011-2881", "CVE-2011-3234", "CVE-2011-3873", "CVE-2011-3875", "CVE-2011-3876", "CVE-2011-3877", "CVE-2011-3878", "CVE-2011-3879", "CVE-2011-3880", "CVE-2011-3881", "CVE-2011-3882", "CVE-2011-3883", "CVE-2011-3884", "CVE-2011-3885", "CVE-2011-3886", "CVE-2011-3887", "CVE-2011-3888", "CVE-2011-3889", "CVE-2011-3890", "CVE-2011-3891", "CVE-2011-3892", "CVE-2011-3893", "CVE-2011-3894", "CVE-2011-3895", "CVE-2011-3896", "CVE-2011-3897", "CVE-2011-3898", "CVE-2011-3900");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (6887828f-0229-11e0-b84d-00262d5ed8ee)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Chrome Releases reports :

Fixed in 15.0.874.121 : [103259] High CVE-2011-3900: Out-of-bounds
write in v8. Credit to Christian Holler.

Fixed in 15.0.874.120 : [100465] High CVE-2011-3892: Double free in
Theora decoder. Credit to Aki Helin of OUSPG. [100492] [100543] Medium
CVE-2011-3893: Out of bounds reads in MKV and Vorbis media handlers.
Credit to Aki Helin of OUSPG. [101172] High CVE-2011-3894: Memory
corruption regression in VP8 decoding. Credit to Andrew Scherkus of
the Chromium development community. [101458] High CVE-2011-3895: Heap
overflow in Vorbis decoder. Credit to Aki Helin of OUSPG. [101624]
High CVE-2011-3896: Buffer overflow in shader variable mapping. Credit
to Ken 'strcpy' Russell of the Chromium development community.
[102242] High CVE-2011-3897: Use-after-free in editing. Credit to
pa_kt reported through ZDI (ZDI-CAN-1416). [102461] Low CVE-2011-3898:
Failure to ask for permission to run applets in JRE7. Credit to Google
Chrome Security Team (Chris Evans).

Fixed in 15.0.874.102 : [86758] High CVE-2011-2845: URL bar spoof in
history handling. Credit to Jordi Chancel. [88949] Medium
CVE-2011-3875: URL bar spoof with drag+drop of URLs. Credit to Jordi
Chancel. [90217] Low CVE-2011-3876: Avoid stripping whitespace at the
end of download filenames. Credit to Marc Novak. [91218] Low
CVE-2011-3877: XSS in appcache internals page. Credit to Google Chrome
Security Team (Tom Sepez) plus independent discovery by Juho Nurminen.
[94487] Medium CVE-2011-3878: Race condition in worker process
initialization. Credit to miaubiz. [95374] Low CVE-2011-3879: Avoid
redirect to chrome scheme URIs. Credit to Masato Kinugawa. [95992] Low
CVE-2011-3880: Don't permit as a HTTP header delimiter. Credit to
Vladimir Vorontsov, ONsec company. [96047] [96885] [98053] [99512]
[99750] High CVE-2011-3881 : Cross-origin policy violations. Credit to
Sergey Glazunov. [96292] High CVE-2011-3882: Use-after-free in media
buffer handling. Credit to Google Chrome Security Team (Inferno).
[96902] High CVE-2011-3883: Use-after-free in counter handling. Credit
to miaubiz. [97148] High CVE-2011-3884: Timing issues in DOM
traversal. Credit to Brian Ryner of the Chromium development
community. [97599] [98064] [98556] [99294] [99880] [100059] High
CVE-2011-3885 : Stale style bugs leading to use-after-free. Credit to
miaubiz. [98773] [99167] High CVE-2011-3886: Out of bounds writes in
v8. Credit to Christian Holler. [98407] Medium CVE-2011-3887: Cookie
theft with javascript URIs. Credit to Sergey Glazunov. [99138] High
CVE-2011-3888: Use-after-free with plug-in and editing. Credit to
miaubiz. [99211] High CVE-2011-3889: Heap overflow in Web Audio.
Credit to miaubiz. [99553] High CVE-2011-3890: Use-after-free in video
source handling. Credit to Ami Fischman of the Chromium development
community. [100332] High CVE-2011-3891: Exposure of internal v8
functions. Credit to Steven Keuchel of the Chromium development
community plus independent discovery by Daniel Divricean.

Fixed in 14.0.835.202 : [93788] High CVE-2011-2876: Use-after-free in
text line box handling. Credit to miaubiz. [95072] High CVE-2011-2877:
Stale font in SVG text handling. Credit to miaubiz. [95671] High
CVE-2011-2878: Inappropriate cross-origin access to the window
prototype. Credit to Sergey Glazunov. [96150] High CVE-2011-2879:
Lifetime and threading issues in audio node handling. Credit to Google
Chrome Security Team (Inferno). [97451] [97520] [97615] High
CVE-2011-2880: Use-after-free in the v8 bindings. Credit to Sergey
Glazunov. [97784] High CVE-2011-2881: Memory corruption with v8 hidden
objects. Credit to Sergey Glazunov. [98089] Critical CVE-2011-3873:
Memory corruption in shader translator. Credit to Zhenyao Mo of the
Chromium development community.

Fixed in 14.0.835.163 : [49377] High CVE-2011-2835: Race condition in
the certificate cache. Credit to Ryan Sleevi of the Chromium
development community. [51464] Low CVE-2011-2836: Infobar the Windows
Media Player plug-in to avoid click-free access to the system Flash.
Credit to electronixtar. [Linux only] [57908] Low CVE-2011-2837: Use
PIC / pie compiler flags. Credit to wbrana. [75070] Low CVE-2011-2838:
Treat MIME type more authoritatively when loading plug-ins. Credit to
Michal Zalewski of the Google Security Team. [76771] High
CVE-2011-2839: Crash in v8 script object wrappers. Credit to Kostya
Serebryany of the Chromium development community. [78427] [83031] Low
CVE-2011-2840: Possible URL bar spoofs with unusual user interaction.
Credit to kuzzcc. [78639] High CVE-2011-2841: Garbage collection error
in PDF. Credit to Mario Gomes. [82438] Medium CVE-2011-2843:
Out-of-bounds read with media buffers. Credit to Kostya Serebryany of
the Chromium development community. [85041] Medium CVE-2011-2844:
Out-of-bounds read with mp3 files. Credit to Mario Gomes. [89219] High
CVE-2011-2846: Use-after-free in unload event handling. Credit to
Arthur Gerkis. [89330] High CVE-2011-2847: Use-after-free in document
loader. Credit to miaubiz. [89564] Medium CVE-2011-2848: URL bar spoof
with forward button. Credit to Jordi Chancel. [89795] Low
CVE-2011-2849: Browser NULL pointer crash with WebSockets. Credit to
Arthur Gerkis. [89991] Medium CVE-2011-3234: Out-of-bounds read in box
handling. Credit to miaubiz. [90134] Medium CVE-2011-2850:
Out-of-bounds read with Khmer characters. Credit to miaubiz. [90173]
Medium CVE-2011-2851: Out-of-bounds read in video handling. Credit to
Google Chrome Security Team (Inferno). [91120] High CVE-2011-2852:
Off-by-one in v8. Credit to Christian Holler. [91197] High
CVE-2011-2853: Use-after-free in plug-in handling. Credit to Google
Chrome Security Team (SkyLined). [92651] [94800] High CVE-2011-2854:
Use-after-free in ruby / table style handing. Credit to Slawomir
Blazek, and independent later discoveries by miaubiz and Google Chrome
Security Team (Inferno). [92959] High CVE-2011-2855: Stale node in
stylesheet handling. Credit to Arthur Gerkis. [93416] High
CVE-2011-2856: Cross-origin bypass in v8. Credit to Daniel Divricean.
[93420] High CVE-2011-2857: Use-after-free in focus controller. Credit
to miaubiz. [93472] High CVE-2011-2834: Double free in libxml XPath
handling. Credit to Yang Dingning from NCNIPC, Graduate University of
Chinese Academy of Sciences. [93497] Medium CVE-2011-2859: Incorrect
permissions assigned to non-gallery pages. Credit to Bernhard 'Bruhns'
Brehm of Recurity Labs. [93587] High CVE-2011-2860: Use-after-free in
table style handling. Credit to miaubiz. [93596] Medium CVE-2011-2861:
Bad string read in PDF. Credit to Aki Helin of OUSPG. [93906] High
CVE-2011-2862: Unintended access to v8 built-in objects. Credit to
Sergey Glazunov. [95563] Medium CVE-2011-2864: Out-of-bounds read with
Tibetan characters. Credit to Google Chrome Security Team (Inferno).
[95625] Medium CVE-2011-2858: Out-of-bounds read with triangle arrays.
Credit to Google Chrome Security Team (Inferno). [95917] Low
CVE-2011-2874: Failure to pin a self-signed cert for a session. Credit
to Nishant Yadant of VMware and Craig Chamberlain (@randomuserid).
High CVE-2011-2875: Type confusion in v8 object sealing. Credit to
Christian Holler.

Fixed in 13.0.782.215 : [89402] High CVE-2011-2821: Double free in
libxml XPath handling. Credit to Yang Dingning from NCNIPC, Graduate
University of Chinese Academy of Sciences. [82552] High CVE-2011-2823:
Use-after-free in line box handling. Credit to Google Chrome Security
Team (SkyLined) and independent later discovery by miaubiz. [88216]
High CVE-2011-2824: Use-after-free with counter nodes. Credit to
miaubiz. [88670] High CVE-2011-2825: Use-after-free with custom fonts.
Credit to wushi of team509 reported through ZDI (ZDI-CAN-1283), plus
indepdendent later discovery by miaubiz. [87453] High CVE-2011-2826:
Cross-origin violation with empty origins. Credit to Sergey Glazunov.
[90668] High CVE-2011-2827: Use-after-free in text searching. Credit
to miaubiz. [91517] High CVE-2011-2828: Out-of-bounds write in v8.
Credit to Google Chrome Security Team (SkyLined). [32-bit only]
[91598] High CVE-2011-2829: Integer overflow in uniform arrays. Credit
to Sergey Glazunov. [Linux only] [91665] High CVE-2011-2839: Buggy
memset() in PDF. Credit to Aki Helin of OUSPG.

Fixed in 13.0.782.107 : [75821] Medium CVE-2011-2358: Always confirm
an extension install via a browser dialog. Credit to Sergey Glazunov.
[78841] High CVE-2011-2359: Stale pointer due to bad line box tracking
in rendering. Credit to miaubiz and Martin Barbella. [79266] Low
CVE-2011-2360: Potential bypass of dangerous file prompt. Credit to
kuzzcc. [79426] Low CVE-2011-2361: Improve designation of strings in
the basic auth dialog. Credit to kuzzcc. [Linux only] [81307] Medium
CVE-2011-2782: File permissions error with drag and drop. Credit to
Evan Martin of the Chromium development community. [83273] Medium
CVE-2011-2783: Always confirm a developer mode NPAPI extension install
via a browser dialog. Credit to Sergey Glazunov. [83841] Low
CVE-2011-2784: Local file path disclosure via GL program log. Credit
to kuzzcc. [84402] Low CVE-2011-2785: Sanitize the homepage URL in
extensions. Credit to kuzzcc. [84600] Low CVE-2011-2786: Make sure the
speech input bubble is always on-screen. Credit to Olli Pettay of
Mozilla. [84805] Medium CVE-2011-2787: Browser crash due to GPU lock
re-entrancy issue. Credit to kuzzcc. [85559] Low CVE-2011-2788: Buffer
overflow in inspector serialization. Credit to Mikolaj Malecki.
[85808] Medium CVE-2011-2789: Use after free in Pepper plug-in
instantiation. Credit to Mario Gomes and kuzzcc. [86502] High
CVE-2011-2790: Use-after-free with floating styles. Credit to miaubiz.
[86900] High CVE-2011-2791: Out-of-bounds write in ICU. Credit to Yang
Dingning from NCNIPC, Graduate University of Chinese Academy of
Sciences. [87148] High CVE-2011-2792: Use-after-free with float
removal. Credit to miaubiz. [87227] High CVE-2011-2793: Use-after-free
in media selectors. Credit to miaubiz. [87298] Medium CVE-2011-2794:
Out-of-bounds read in text iteration. Credit to miaubiz. [87339]
Medium CVE-2011-2795: Cross-frame function leak. Credit to Shih
Wei-Long. [87548] High CVE-2011-2796: Use-after-free in Skia. Credit
to Google Chrome Security Team (Inferno) and Kostya Serebryany of the
Chromium development community. [87729] High CVE-2011-2797:
Use-after-free in resource caching. Credit to miaubiz. [87815] Low
CVE-2011-2798: Prevent a couple of internal schemes from being web
accessible. Credit to sirdarckcat of the Google Security Team. [87925]
High CVE-2011-2799: Use-after-free in HTML range handling. Credit to
miaubiz. [88337] Medium CVE-2011-2800: Leak of client-side redirect
target. Credit to Juho Nurminen. [88591] High CVE-2011-2802: v8 crash
with const lookups. Credit to Christian Holler. [88827] Medium
CVE-2011-2803: Out-of-bounds read in Skia paths. Credit to Google
Chrome Security Team (Inferno). [88846] High CVE-2011-2801:
Use-after-free in frame loader. Credit to miaubiz. [88889] High
CVE-2011-2818: Use-after-free in display box rendering. Credit to
Martin Barbella. [89142] High CVE-2011-2804: PDF crash with nested
functions. Credit to Aki Helin of OUSPG. [89520] High CVE-2011-2805:
Cross-origin script injection. Credit to Sergey Glazunov. [90222] High
CVE-2011-2819: Cross-origin violation in base URI handling. Credit to
Sergey Glazunov.

Fixed in 12.0.742.112 : [77493] Medium CVE-2011-2345: Out-of-bounds
read in NPAPI string handling. Credit to Philippe Arteau. [84355] High
CVE-2011-2346: Use-after-free in SVG font handling. Credit to miaubiz.
[85003] High CVE-2011-2347: Memory corruption in CSS parsing. Credit
to miaubiz. [85102] High CVE-2011-2350: Lifetime and re-entrancy
issues in the HTML parser. Credit to miaubiz. [85177] High
CVE-2011-2348: Bad bounds check in v8. Credit to Aki Helin of OUSPG.
[85211] High CVE-2011-2351: Use-after-free with SVG use element.
Credit to miaubiz. [85418] High CVE-2011-2349: Use-after-free in text
selection. Credit to miaubiz.

Fixed in 12.0.742.91 : [73962] [79746] High CVE-2011-1808:
Use-after-free due to integer issues in float handling. Credit to
miaubiz. [75496] Medium CVE-2011-1809: Use-after-free in accessibility
support. Credit to Google Chrome Security Team (SkyLined). [75643] Low
CVE-2011-1810: Visit history information leak in CSS. Credit to Jesse
Mohrland of Microsoft and Microsoft Vulnerability Research (MSVR).
[76034] Low CVE-2011-1811: Browser crash with lots of form
submissions. Credit to 'DimitrisV22'. [77026] Medium CVE-2011-1812:
Extensions permission bypass. Credit to kuzzcc. [78516] High
CVE-2011-1813: Stale pointer in extension framework. Credit to Google
Chrome Security Team (Inferno). [79362] Medium CVE-2011-1814: Read
from uninitialized pointer. Credit to Eric Roman of the Chromium
development community. [79862] Low CVE-2011-1815: Extension script
injection into new tab page. Credit to kuzzcc. [80358] Medium
CVE-2011-1816: Use-after-free in developer tools. Credit to kuzzcc.
[81916] Medium CVE-2011-1817: Browser memory corruption in history
deletion. Credit to Collin Payne. [81949] High CVE-2011-1818:
Use-after-free in image loader. Credit to miaubiz. [83010] Medium
CVE-2011-1819: Extension injection into chrome:// pages. Credit to
Vladislavas Jarmalis, plus subsequent independent discovery by Sergey
Glazunov. [83275] High CVE-2011-2332: Same origin bypass in v8. Credit
to Sergey Glazunov. [83743] High CVE-2011-2342: Same origin bypass in
DOM. Credit to Sergey Glazunov.

Fixed in 11.0.696.71 : [72189] Low CVE-2011-1801: Pop-up blocker
bypass. Credit to Chamal De Silva. [82546] High CVE-2011-1804: Stale
pointer in floats rendering. Credit to Martin Barbella. [82873]
Critical CVE-2011-1806: Memory corruption in GPU command buffer.
Credit to Google Chrome Security Team (Cris Neckar). [82903] Critical
CVE-2011-1807: Out-of-bounds write in blob handling. Credit to Google
Chrome Security Team (Inferno) and Kostya Serebryany of the Chromium
development community.

Fixed in 11.0.696.68 : [64046] High CVE-2011-1799: Bad casts in
Chromium WebKit glue. Credit to Google Chrome Security Team
(SkyLined). [80608] High CVE-2011-1800: Integer overflows in SVG
filters. Credit to Google Chrome Security Team (Cris Neckar).

Fixed in 11.0.696.57 : [61502] High CVE-2011-1303: Stale pointer in
floating object handling. Credit to Scott Hess of the Chromium
development community and Martin Barbella. [70538] Low CVE-2011-1304:
Pop-up block bypass via plug-ins. Credit to Chamal De Silva. [Linux /
Mac only] [70589] Medium CVE-2011-1305: Linked-list race in database
handling. Credit to Kostya Serebryany of the Chromium development
community. [71586] Medium CVE-2011-1434: Lack of thread safety in MIME
handling. Credit to Aki Helin. [72523] Medium CVE-2011-1435: Bad
extension with 'tabs' permission can capture local files. Credit to
Cole Snodgrass. [Linux only] [72910] Low CVE-2011-1436: Possible
browser crash due to bad interaction with X. Credit to miaubiz.
[73526] High CVE-2011-1437: Integer overflows in float rendering.
Credit to miaubiz. [74653] High CVE-2011-1438: Same origin policy
violation with blobs. Credit to kuzzcc. [Linux only] [74763] High
CVE-2011-1439: Prevent interference between renderer processes. Credit
to Julien Tinnes of the Google Security Team. [75186] High
CVE-2011-1440: Use-after-free with <ruby> tag and CSS. Credit to Jose
A. Vazquez. [75347] High CVE-2011-1441: Bad cast with floating select
lists. Credit to Michael Griffiths. [75801] High CVE-2011-1442:
Corrupt node trees with mutation events. Credit to Sergey Glazunov and
wushi of team 509. [76001] High CVE-2011-1443: Stale pointers in
layering code. Credit to Martin Barbella. [Linux only] [76542] High
CVE-2011-1444: Race condition in sandbox launcher. Credit to Dan
Rosenberg. Medium CVE-2011-1445: Out-of-bounds read in SVG. Credit to
wushi of team509. [76666] [77507] [78031] High CVE-2011-1446: Possible
URL bar spoofs with navigation errors and interrupted loads. Credit to
kuzzcc. [76966] High CVE-2011-1447: Stale pointer in drop-down list
handling. Credit to miaubiz. [77130] High CVE-2011-1448: Stale pointer
in height calculations. Credit to wushi of team509. [77346] High
CVE-2011-1449: Use-after-free in WebSockets. Credit to Marek
Majkowski. Low CVE-2011-1450: Dangling pointers in file dialogs.
Credit to kuzzcc. [77463] High CVE-2011-1451: Dangling pointers in DOM
id map. Credit to Sergey Glazunov. [77786] Medium CVE-2011-1452: URL
bar spoof with redirect and manual reload. Credit to Jordi Chancel.
[79199] High CVE-2011-1454: Use-after-free in DOM id handling. Credit
to Sergey Glazunov. [79361] Medium CVE-2011-1455: Out-of-bounds read
with multipart-encoded PDF. Credit to Eric Roman of the Chromium
development community. [79364] High CVE-2011-1456: Stale pointers with
PDF forms. Credit to Eric Roman of the Chromium development community.

Fixed in 10.0.648.205 : [75629] Critical CVE-2011-1301: Use-after-free
in the GPU process. Credit to Google Chrome Security Team (Inferno).
[78524] Critical CVE-2011-1302: Heap overflow in the GPU process.
Credit to Christoph Diehl.

Fixed in 10.0.648.204 : [72517] High CVE-2011-1291: Buffer error in
base string handling. Credit to Alex Turpin. [73216] High
CVE-2011-1292: Use-after-free in the frame loader. Credit to Slawomir
Blazek. [73595] High CVE-2011-1293: Use-after-free in HTMLCollection.
Credit to Sergey Glazunov. [74562] High CVE-2011-1294: Stale pointer
in CSS handling. Credit to Sergey Glazunov. [74991] High
CVE-2011-1295: DOM tree corruption with broken node parentage. Credit
to Sergey Glazunov. [75170] High CVE-2011-1296: Stale pointer in SVG
text handling. Credit to Sergey Glazunov.

Fixed in 10.0.648.133 : [75712] High Memory corruption in style
handling. Credit to Vincenzo Iozzo, Ralf Philipp Weinmann and Willem
Pinckaers reported through ZDI.

Fixed in 10.0.648.127 : [42765] Low Possible to navigate or close the
top location in a sandboxed frame. Credit to sirdarckcat of the Google
Security Team. [Linux only] [49747] Low Work around an X server bug
and crash with long messages. Credit to Louis Lang. [Linux only]
[66962] Low Possible browser crash with parallel print()s. Credit to
Aki Helin of OUSPG. [69187] Medium Cross-origin error message leak.
Credit to Daniel Divricean. [69628] High Memory corruption with
counter nodes. Credit to Martin Barbella. [70027] High Stale node in
box layout. Credit to Martin Barbella. [70336] Medium Cross-origin
error message leak with workers. Credit to Daniel Divricean. [70442]
High Use after free with DOM URL handling. Credit to Sergey Glazunov.
[Linux only] [70779] Medium Out of bounds read handling unicode
ranges. Credit to miaubiz. [70877] High Same origin policy bypass in
v8. Credit to Daniel Divricean. [70885] [71167] Low Pop-up blocker
bypasses. Credit to Chamal de Silva. [71763] High Use-after-free in
document script lifetime handling. Credit to miaubiz. [71788] High
Out-of-bounds write in the OGG container. Credit to Google Chrome
Security Team (SkyLined); plus subsequent independent discovery by
David Weston of Microsoft and MSVR. [72028] High Stale pointer in
table painting. Credit to Martin Barbella. [73026] High Use of corrupt
out-of-bounds structure in video code. Credit to Tavis Ormandy of the
Google Security Team. [73066] High Crash with the DataView object.
Credit to Sergey Glazunov. [73134] High Bad cast in text rendering.
Credit to miaubiz. [73196] High Stale pointer in WebKit context code.
Credit to Sergey Glazunov. [73716] Low Leak of heap address in XSLT.
Credit to Google Chrome Security Team (Chris Evans). [73746] High
Stale pointer with SVG cursors. Credit to Sergey Glazunov. [74030]
High DOM tree corruption with attribute handling. Credit to Sergey
Glazunov. [74662] High Corruption via re-entrancy of RegExp code.
Credit to Christian Holler. [74675] High Invalid memory access in v8.
Credit to Christian Holler.

Fixed in 9.0.597.107 : [54262] High URL bar spoof. Credit to Jordi
Chancel. [63732] High Crash with JavaScript dialogs. Credit to Sergey
Radchenko. [68263] High Stylesheet node stale pointer. Credit to
Sergey Glazunov. [68741] High Stale pointer with key frame rule.
Credit to Sergey Glazunov. [70078] High Crash with forms controls.
Credit to Stefan van Zanden. [70244] High Crash in SVG rendering.
Credit to Slawomir Blazek. [64-bit Linux only] [70376] Medium
Out-of-bounds read in pickle deserialization. Credit to Evgeniy
Stepanov of the Chromium development community. [71114] High Stale
node in table handling. Credit to Martin Barbella. [71115] High Stale
pointer in table rendering. Credit to Martin Barbella. [71296] High
Stale pointer in SVG animations. Credit to miaubiz. [71386] High Stale
nodes in XHTML. Credit to wushi of team509. [71388] High Crash in
textarea handling. Credit to wushi of team509. [71595] High Stale
pointer in device orientation. Credit to Sergey Glazunov. [71717]
Medium Out-of-bounds read in WebGL. Credit to miaubiz. [71855] High
Integer overflow in textarea handling. Credit to miaubiz. [71960]
Medium Out-of-bounds read in WebGL. Credit to Google Chrome Security
Team (Inferno). [72214] High Accidental exposure of internal extension
functions. Credit to Tavis Ormandy of the Google Security Team.
[72437] High Use-after-free with blocked plug-ins. Credit to Chamal de
Silva. [73235] High Stale pointer in layout. Credit to Martin
Barbella.

Fixed in 9.0.597.94 : [67234] High Stale pointer in animation event
handling. Credit to Rik Cabanier. [68120] High Use-after-free in SVG
font faces. Credit to miaubiz. [69556] High Stale pointer with
anonymous block handling. Credit to Martin Barbella. [69970] Medium
Out-of-bounds read in plug-in handling. Credit to Bill Budge of
Google. [70456] Medium Possible failure to terminate process on
out-of-memory condition. Credit to David Warren of CERT/CC.

Fixed in 9.0.597.84 : [Mac only] [42989] Low Minor sandbox leak via
stat(). Credit to Daniel Cheng of the Chromium development community.
[55831] High Use-after-free in image loading. Credit to Aki Helin of
OUSPG. [59081] Low Apply some restrictions to cross-origin drag +
drop. Credit to Google Chrome Security Team (SkyLined) and the Google
Security Team (Michal Zalewski, David Bloom). [62791] Low Browser
crash with extension with missing key. Credit to Brian Kirchoff.
[64051] High Crashing when printing in PDF event handler. Credit to
Aki Helin of OUSPG. [65669] Low Handle merging of autofill profiles
more gracefully. Credit to Google Chrome Security Team (Inferno). [Mac
only] [66931] Low Work around a crash in the Mac OS 10.5 SSL
libraries. Credit to Dan Morrison. [68244] Low Browser crash with bad
volume setting. Credit to Matthew Heidermann. [69195] Critical Race
condition in audio handling. Credit to the gamers of Reddit!

Fixed in 8.0.552.237 : [58053] Medium Browser crash in extensions
notification handling. Credit to Eric Roman of the Chromium
development community. [65764] High Bad pointer handling in node
iteration. Credit to Sergey Glazunov. [66334] High Crashes when
printing multi-page PDFs. Credit to Google Chrome Security Team (Chris
Evans). [66560] High Stale pointer with CSS + canvas. Credit to Sergey
Glazunov. [66748] High Stale pointer with CSS + cursors. Credit to Jan
Tosovsk. [67100] High Use after free in PDF page handling. Credit to
Google Chrome Security Team (Chris Evans). [67208] High Stack
corruption after PDF out-of-memory condition. Credit to Jared Allar of
CERT. [67303] High Bad memory access with mismatched video frame
sizes. Credit to Aki Helin of OUSPG; plus independent discovery by
Google Chrome Security Team (SkyLined) and David Warren of CERT.
[67363] High Stale pointer with SVG use element. Credited anonymously;
plus indepdent discovery by miaubiz. [67393] Medium Uninitialized
pointer in the browser triggered by rogue extension. Credit to kuzzcc.
[68115] High Vorbis decoder buffer overflows. Credit to David Warren
of CERT. [68170] High Buffer overflow in PDF shading. Credit to Aki
Helin of OUSPG. [68178] High Bad cast in anchor handling. Credit to
Sergey Glazunov. [68181] High Bad cast in video handling. Credit to
Sergey Glazunov. [68439] High Stale rendering node after DOM node
removal. Credit to Martin Barbella; plus independent discovery by
Google Chrome Security Team (SkyLined). [68666] Critical Stale pointer
in speech handling. Credit to Sergey Glazunov.

Fixed in 8.0.552.224 : [64-bit Linux only] [56449] High Bad validation
for message deserialization on 64-bit builds. Credit to Lei Zhang of
the Chromium development community. [60761] Medium Bad extension can
cause browser crash in tab handling. Credit to kuzzcc. [63529] Low
Browser crash with NULL pointer in web worker handling. Credit to
Nathan Weizenbaum of Google. [63866] Medium Out-of-bounds read in CSS
parsing. Credit to Chris Rohlf. [64959] High Stale pointers in cursor
handling. Credit to Slawomir Blazek and Sergey Glazunov.

Fixed in 8.0.552.215 : [17655] Low Possible pop-up blocker bypass.
Credit to Google Chrome Security Team (SkyLined). [55745] Medium
Cross-origin video theft with canvas. Credit to Nirankush Panchbhai
and Microsoft Vulnerability Research (MSVR). [56237] Low Browser crash
with HTML5 databases. Credit to Google Chrome Security Team (Inferno).
[58319] Low Prevent excessive file dialogs, possibly leading to
browser crash. Credit to Cezary Tomczak (gosu.pl). [59554] High Use
after free in history handling. Credit to Stefan Troger. [Linux / Mac]
[59817] Medium Make sure the 'dangerous file types' list is uptodate
with the Windows platforms. Credit to Billy Rios of the Google
Security Team. [61701] Low Browser crash with HTTP proxy
authentication. Credit to Mohammed Bouhlel. [61653] Medium
Out-of-bounds read regression in WebM video support. Credit to Google
Chrome Security Team (Chris Evans), based on earlier testcases from
Mozilla and Microsoft (MSVR). [62127] High Crash due to bad indexing
with malformed video. Credit to miaubiz. [62168] Medium Possible
browser memory corruption via malicious privileged extension. Credit
to kuzzcc. [62401] High Use after free with SVG animations. Credit to
Slawomir Blazek. [63051] Medium Use after free in mouse dragging event
handling. Credit to kuzzcc. [63444] High Double free in XPath
handling. Credit to Yang Dingning from NCNIPC, Graduate University of
Chinese Academy of Sciences.

Fixed in 7.0.517.44 : [51602] High Use-after-free in text editing.
Credit to David Bloom of the Google Security Team, Google Chrome
Security Team (Inferno) and Google Chrome Security Team (Cris Neckar).
[55257] High Memory corruption with enormous text area. Credit to
wushi of team509. [58657] High Bad cast with the SVG use element.
Credit to the kuzzcc. [58731] High Invalid memory read in XPath
handling. Credit to Bui Quang Minh from Bkis (www.bkis.com). [58741]
High Use-after-free in text control selections. Credit to 'vkouchna'.
[Linux only] [59320] High Integer overflows in font handling. Credit
to Aki Helin of OUSPG. [60055] High Memory corruption in libvpx.
Credit to Christoph Diehl. [60238] High Bad use of destroyed frame
object. Credit to various developers, including 'gundlach'. [60327]
[60769] [61255] High Type confusions with event objects. Credit to
'fam.lam' and Google Chrome Security Team (Inferno). [60688] High
Out-of-bounds array access in SVG handling. Credit to wushi of
team509.

Fixed in 7.0.517.43 : [48225] [51727] Medium Possible autofill /
autocomplete profile spamming. Credit to Google Chrome Security Team
(Inferno). [48857] High Crash with forms. Credit to the Chromium
development community. [50428] Critical Browser crash with form
autofill. Credit to the Chromium development community. [51680] High
Possible URL spoofing on page unload. Credit to kuzzcc; plus
independent discovery by Jordi Chancel. [53002] Low Pop-up block
bypass. Credit to kuzzcc. [53985] Medium Crash on shutdown with Web
Sockets. Credit to the Chromium development community. [Linux only]
[54132] Low Bad construction of PATH variable. Credit to Dan
Rosenberg, Virtual Security Research. [54500] High Possible memory
corruption with animated GIF. Credit to Simon Schaak. [Linux only]
[54794] High Failure to sandbox worker processes on Linux. Credit to
Google Chrome Security Team (Chris Evans). [56451] High Stale elements
in an element map. Credit to Michal Zalewski of the Google Security
Team."
  );
  # http://googlechromereleases.blogspot.com/search/label/Stable%20updates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29fa020e"
  );
  # http://www.freebsd.org/ports/portaudit/6887828f-0229-11e0-b84d-00262d5ed8ee.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68c666ce"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"chromium<15.0.874.121")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
