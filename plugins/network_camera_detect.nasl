#
# (C) Tenable Network Security, Inc.
#

# References:
# http://johnny.ihackstuff.com/ghdb.php?function=summary&cat=18
# http://www.net-security.org/vuln.php?id=3288
#

include("compat.inc");

if (description)
{
 script_id(33523);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2013/12/17 11:44:10 $");

 script_name(english:"Network Camera Web Server Detection");
 script_summary(english:"Detect network camera");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is a network camera.");
 script_set_attribute(attribute:"description", value:"The remote web server controls a network camera.");
 script_set_attribute(attribute:"solution", value:
"If this is not a public webcam, make sure that the camera is
configured to require credentials or is protected with a firewall to
prevent anyone from viewing images, moving the camera, or changing its
parameters.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/17");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl");
 script_require_ports(80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded: 1);
if (! port) exit(0);

# Possible matchs:
# server	Server field (may be "" if there is *no* server field)
# server_re	idem, regex
# url		special page
# title		title found in the special page
# title_re
# body		string found in the page
# body_re	regex found in the page
# realm         Basic auth realm
# name		description of the camera

i = 0;
name[i] = "Techno Vision Security System Ver. 2.0";
server[i] = "Techno Vision Security System Ver. 2.0";
url[i] = "/live.html";
body[i] = "nCamera";
i ++;
name[i] = "BlueNet Video Viewer";
title_re[i] = "BlueNet Video Viewer Version [0-9.]+[a-z]?";
url[i] = "/cgi-bin/client_execute.cgi?tUD=0";
body[i] = '<OBJECT ID="NVS" classid="clsid:99A7E374-3E8E-4C78-A054-25522DC03DA2"';
i ++;
name[i] = "Wave Browser";
url[i] = "/wrcontrollite.ssi";
title_re[i] = "Wave Browser 1\.[0-9]";
body[i] = '<OBJECT CLASSID="clsid:5220cb21-c88d-11cf-b347-00aa00a28331" VIEWASTEXT id="Microsoft_Licensed_Class_Manager_1_0"1>';
i ++;
name[i] = "Divar web client";
body[i] = '<OBJECT CLASSID="clsid:E3A1E133-6730-4EE4-8CB2-C1267841E9BA" ID=proxy>';
url[i] = "/login1.htm";
i ++;

name[i] = "AV-TECH AVC787 Digital Video Recorder";
body[i] = "IP Surveillance New Generation";
# server[i] = "SQ-WEBCAM";
# server[i] = "AV-TECH AV787 Video Web Server";
url[i] = "/";
title[i] = "--- VIDEO WEB SERVER ---";
i ++;
name[i] = "Hunt Electronics webcam";
title[i] = "LAN Camera";
url[i] = "/";
body[i] = '<OBJECT ID=\\"APOLancam2\\"';
# See also:
# <META NAME="AUTHOR" CONTENT="Eric Chang">
# <META NAME="Version" CONENT="0.22">
# <META NAME="KEYWORDS" CONTENT="lancam, webcam, ipcam, camera, nvr, network, netmeeting, wireless, security, remote, surveillance">
# <META NAME="ROBOTS" CONTENT="ALL">
# <META NAME="GOOGLEBOT" CONTENT="ALL">
i ++;
name[i] = "WxGoos webcam";
server_re[i] = "I\.T\. Watchdogs, Inc\. Embedded Web Server \(v[0-9]\.[0-9]+[a-z]?\)";	# I.T. Watchdogs, Inc. Embedded Web Server (v2.57d)
title_re[i] = "WxGoos-[0-9].*";
i ++;
name[i] = "D-link DCS2100 webcam";
server[i] = "D-Link MiniAVServer";
url[i] = "/";
i ++;
name[i] = "SiteZAP WebCam Control";
server_re[i] = "SiteZAP [0-9]+\.[0-9]+\.[0-9]+";	#SiteZAP 6.0.5
url[i] = "/";
i ++;
name[i] = "WebCam XP";
server[i] = "webcamXP";
url[i] = "/";
title[i] = "my webcamXP server!";
i ++;
name[i] = "Panasonic WJ-NT104 webcam";
url[i] = "/";
title_re[i] = "WJ-NT104 MAIN PAGE.*";
i ++;
name[i] = "EverFocus webcam";
title_re[i] = "EverFocus EDSR[0-9]* Applet \([0-9.]+\)";
body[i] = '<PARAM NAME=archive VALUE="edsrcomm.jar">';
server[i] = "HyNetOS/2.0";
i ++;
name[i] = "AXIS 240 webcam";
title[i] = "AXIS 240 Camera Server";
server[i] = "";
i ++;
name[i] = "StarDot NetCam";
title[i] = "NetCam Live Image";
server_re[i] = "Boa/0\.[0-9]+\.[0-9]+"; #  Boa/0.93.15
i ++;
# Unfortunately, this may be anywhere - it is often /somedir/Destination.htm
name[i] = "Supervision webcam";
title[i] = "SupervisionCam Protocol";
body_re[i] = '<META NAME="keywords" CONTENT="Supervision, SupervisionCam, .*">';
i ++;
name[i] = "LiveView AXIS 205 Network Camera";
title_re[i] = "Live view / - AXIS [0-9]+ (Network Camera )?version [0-9]+\.[0-9]+"; # Live view / - AXIS 205 version 4.03
server[i] = "";
url[i] = "/";
i ++;
name[i] = "EverFocus eDR400 webcam";
title[i] = "Welcome to eDR400--login";
body[i] = "EverFocus Electronics Corp.";
url[i] = "/";
i ++;
name[i] = "EverFocus EDR1600 webcam";
title[i] = "Welcome to EDR1600--login";
url[i] = "/";
body[i] = "EverFocus Electronics Corp.";
i ++;
name[i] = "EverFocus webcam (eg, EDVR9D1, EDR810H)";
title[i] = "Remote Viewer";
server[i] = "http server/everfocus";
url[i] = "/login.html?1600&1";
i ++;
name[i] = "EverFocus DVR (eg, ECOR4D)";
title[i] = "Digital Video Recorder";
body[i] = 'ECORViewer';
url[i] = "/login.html?1600";
i ++;
name[i] = "Sony SNC-RZ30 webcam";
server_re[i] = "NetEVI/2\.[0-2][0-9][a-z]?"; # NetEVI/2.20a / NetEVI/2.24
url[i] = "/";
i ++;
name[i] = "Linksys Wireless-G webcam";
title[i] = "Linksys Wireless-G Internet Video Camera";
server_re[i] = "thttpd/2\.[0-9]+[a-z]+";	# thttpd/2.20b
i ++;
name[i] = "Linksys Compact Wireless-G Internet Video Camera";
server_re[i] = "Boa/0\.[0-9]+\.[0-9]+"; # Boa/0.94.13
title[i] = "Linksys Compact Wireless-G Internet Video Camera";
i ++;
name[i] = "Linksys Compact Wireless-G Internet Video Camera";
server_re[i] = "Boa/0\.[0-9]+\.[0-9]+"; # Boa/0.94.13
title[i] = "Wireless-G-Kompakt-Internet-Videokamera von Linksys";
i ++;
name[i] = "mmEye webcam";
server_re[i] = " Apache/1\.3\.[0-9]+ +\(Unix\)";	#  Apache/1.3.0 (Unix)
title[i] = "Brains, Corp. mmEye-WL";
body[i] = '<a href=http://www.brains.co.jp/mmeye/><b>http://www.brains.co.jp/mmeye/</b></a>';
i ++;
name[i] = "V-Gear BEE webcam";
server_re[i] = "Indy/9\.[0-9]+\.[0-9]+";	# Indy/9.00.10
title[i] = "V-Gear BEE";
i ++;
name[i] = "iVISTA webcam";
server_re[i] = "Apache/1\.3\.[0-9]+ +\(Win32\)";	# Apache/1.3.17 (Win32)
body[i] = "<!-- IV-826 iVISTA Generated File : Do not delete this line -->";
title[i] = "iVISTA Main Page";
i ++;
name[i] = "AXIS 200 webcam";
server[i] = "";
title[i] = "The AXIS 200 Home Page";
i ++;

name[i] = "JVC V.Networks Network Video Recorder";
url[i] = "/";
title[i] = "V.Networks [Top]";
body[i] = "Welcome to the Web V.Networks";
server[i] = "JVC/";
i++;

name[i] = "Lorax Camera System";
url[i] = "/";
title[i] = "";
body[i] = 'location.href="Ctl/index.htm?Cus?Audio';
server[i] = "WYM/";
i++;

name[i] = "Panasonic WV-NM100";
url[i] = "/";
title[i] = "WV-NM100 Network Camera";
body[i] = 'function ope_view()';
i++;

url[i] = "/";
name[i] = "VideoInspector (Intelligent Security Systems)";
server[i] = "ISS-HttpMod/1.0";
body_re[i] = "[^A-Za-z0-9]NISS400[^A-Za-z0-9]";
i ++;

name[i] = "GuardEye 3.53 (goldensoft)";
url[i] = "/";
title[i] = "GuardEyes 3.53";
body[i] = 'onMouseOut="MM_swapImgRestore()"';
i ++;

name[i] = "EyeSpyFX";
url[i] = "/eyespyfx_large.jsp";
title[i] = "EyeSpyFX";
body[i] = "document.WebCamApplet.ZoomIn();";
i ++;
name[i] = "Veo Observer XT";
server[i] = "Observer XT (c) Veo";
url[i] = "/en/index.html";
title[i] = "Veo Observer XT";
i ++;
name[i] = "iGuard webcam";
url[i] = "/Admins/WebCam.vtml";
server_re[i] = 'iGuard Embedded Web Server/[0-9.A-Z]+ .*'; # iGuard Embedded Web Server/3.6.5789A (FPS110) SN:VK-2003-01BE-114A
title[i] = "Web Camera";
i ++;
name[i] = "NetBotz webcam";
server_re[i] = "Allegro-Software-RomPager/3\.[0-9]+";	# Allegro-Software-RomPager/3.03
title[i] = "Device Status Summary Page";
url[i] = "/status.html";
body[i] = '<IMG alt="cam image"';
i ++;
name[i] = "Mobotix webcam";	# M10?
url[i] = "/cgi-bin/guestimage.html";
body[i]  = '<meta name="publisher" content="MOBOTIX AG, Germany">';
i ++;
name[i] = "Mobotix webcam";
url[i] = "/pda/";
title[i] = "MOBOTIX PDA-Seiten";
server[i] = "";
i ++;
name[i] = "Industrial Video & Control webcam";
url[i] = "/ivc2/Backup/IVC1/html/index.htm";	# Probably other URLs...
title[i] = "IVC Control Panel";
body[i] = '<OBJECT classid="clsid:2BA48874-7659-4EE7-B8C6-4FD109E9AD93" id="EnSecClientActiveX" ></OBJECT>';
i ++;
name[i] = "Intellinet webcam";
title[i] = "network camera";
server[i] = "GoAhead-Webs";
url[i] = "/web/main_activex.asp";
i ++;
name[i] = "Intellinet webcam";
title[i] = "Network IP Camera";
server[i] = "Boa/";
url[i] = "/index.cgi";
i ++;
name[i] = "DCS-950 webcam";
title_re[i] = "DCS-950G?";
server[i] = "GoAhead-Webs";
url[i] = "/web/login.asp";
i ++;
name[i] = "Sony SNT-V304 Video Network Station";
title[i] = "SONY SNT-V304 Video Network Station";
url[i] = "/view/hsrindex.shtml";
i ++;
name[i] = "GeoVision webcam";
url[i] = "/JPGLogin.htm";
# title[i] = "Password";
server[i] = "GeoHttpServer";
i ++;
name[i] = "Active WebCam";
title[i] = "Active WebCam Page";
url[i] = "/Webcam/webcam.html";	# Might be elsewhere, unfortunately
body[i] = '<meta name="GENERATOR" content="Active WebCam 6.8 (http://www.pysoft.com) [JON]">';
i ++;
name[i] = "Vivotek webcam";
url[i] = "/cgi-bin/camctrl.cgi";
body[i] = '<!-- "@(#)camctrl_head_top.tmpl v2.60c 2004-11-17" -->';
i ++;
name[i] = "Vivotek webcam";
url[i] = "/cgi-bin/ctrldirect.cgi";
title[i] = 'Direct Control Frame';
i ++;
name[i] = "Vivotek webcam";
server[i] = "Vivotek Network Camera";
i ++;

name[i] = "Philips WebEye internet Camera Server";
url[i] = "/login.ml";
server_re[i] = "wg_httpd/1\.[0-9]+ *\(based Boa/0\.[0-9]+[a-z]\)"; # wg_httpd/1.0(based Boa/0.92q)
title[i] = "NetCam User Login";
i ++;
name[i] = "WebThru webcam";
url[i] = "/login.ml";
server_re[i] = "wg_httpd/1\.[0-9]+ *\(based Boa/0\.[0-9]+[a-z]\)";	# wg_httpd/1.0(based Boa/0.92q)
title_re[i] = "Web[tT]hru User Login";
i ++;
name[i] = "liveCT WebEye internet Camera Server";
url[i] = "/login.ml";
server_re[i] = "wg_httpd/1\.[0-9]+ *\(based Boa/0\.[0-9]+[a-z]\)";
title[i] = "WebEye User Login";
i ++;

name[i] = "Toshiba webcam";
url[i] = "/user_view_S.htm";
title[i] = "TOSHIBA Network Camera User Viewer for Single-Screen Display";
server[i] = "";
i ++;
name[i] = "Canon webview";
url[i] = "/sample/LvAppl/lvappl.htm";
server_re[i] = "Boa/0\.[0-9]+[a-z]";	# Boa/0.92o
title[i] = "LiveApplet";
body_re[i] = '<applet +archive="LiveApplet\\.zip" +codebase=';
i++;
name[i] = "  AXIS 2400 Video Server";
server_re[i] = "Boa/0\.[0-9]+[a-z]";	# Boa/0.92o
url[i] = "/index.shtml";
title[i] = "AXIS 2400 Video Server";
i ++;
name[i] = "AXIS 2420 Network Camera";
server_re[i] = "Boa/0\.[0-9]+[a-z]";	# Boa/0.92o
url[i] = "/index.shtml";
title[i] = "AXIS 2420 Network Camera";
i++;
name[i] = "Sony SNC-RZ30 webcam";
server_re[i] = "NetEVI/2\.[0-2][0-9][a-z]?"; # NetEVI/2.20a / NetEVI/2.24
url[i] = "/home/homeJ.html";
title[i] = "SNC-RZ30 HOME";
i ++;
server_re[i] = "NetEVI/[0-9]+\.[0-9]+";	# NetEVI/3.03
name[i] = "Sony SNC-RZ30 webcam";
url[i] = "/home/homeJ.html";
title[i] = "SNC-RZ30 HOME";
i ++;
server_re[i] = "NetZoom/[0-9]+\.[0-9]+";	# NetZoom/1.02
name[i] = "Sony SNC-Z20 webcam";
url[i] = "/home/homeJ.html";
title[i] = "SNC-Z20 HOME";
i ++;
name[i] = "Panasonic webcam";
url[i] = "/ViewerFrame?Mode=Motion";
body_re[i] = '<FRAME[ \t]+SCROLLING=no[ \t]+SRC="nphControlCamera\\?';
i ++;
name[i] = "Seyeon FlexWATCH webcam";
url[i] = "/app/idxasp.html";
server[i] = "FlexWATCH-Webs";
i ++;
name[i] = "Seyeon FlexWATCH webcam";
url[i] = "/app/idxasp.html";	# The double / is an exploit, in fact!
body[i] = ' src="applet/toolas.html" ';
i ++;
name[i] = "MOBOTIX webcam";
url[i] = "/control/userimage.html";
body[i] = '<meta name="publisher" content="MOBOTIX AG, Germany">';
server[i] = "thttpd/2.19-MX Jan 24 2006";
realm[i] = "MOBOTIX Camera User";
i++;

name[i] = "AXIS 210 Network Camera";
url[i] = "/view/index.shtml";
server[i] = "";
title_re[i] = "Live view +- AXIS 210 Network Camera( version [0-9]+\.[0-9]+)?";
i++;

name[i] = "AXIS 213 webcam";
server[i] = "";
url[i] = "/view/index.shtml";
title_re[i] = "Live view +- AXIS 213 PTZ Network Camera( version [0-9]+\.[0-9]+)?";	# Live view  - AXIS 213 PTZ Network Camera version 4.03
i ++;
name[i] = "AXIS 211 webcam";
server[i] = "";
url[i] = "/view/index.shtml";
title_re[i] = "Live view +- AXIS 211 Network Camera( version [0-9]+\.[0-9]+)?";
# Live view  - AXIS 211 Network Camera version 4.11
# Live view  - AXIS 211 Network Camera
i ++;
name[i] = "AXIS 2130R PTZ Network Camera";
url[i] = "/view/view.shtml";
title[i] = "AXIS 2130R PTZ Network Camera";
server_re[i] = "Boa/0\.[0-9]+[a-z]"; #  Boa/0.92o
i ++;
name[i] = "AXIS 241Q Video Server";
url[i] = "/view/view.shtml";
title_re[i] = "Live view  - AXIS 241Q Video Server version [0-9.]+";
body[i] = '<EMBED src="/axis-cgi/mjpg/video.swf?resolution=';
i ++;
name[i] = "AXIS Network Camera";
server_re[i] = "Boa/0\.[0-9]+[a-z]";	# Boa/0.92o
url[i] = "/view/view.shtml";
title_re[i] = "Axis [0-9]+ Network Camera [0-9]+\.[0-9]+";
i++;
# Catchall for AXIS
name[i] = "AXIS webcam";
url[i] = "/view/view.shtml";
title_re[i] = "AXIS [0-9]+[A-Z]* [A-Z]+ Network Camera";
server_re[i] = "Boa/0\.[0-9]+[0-9.a-z]*";
i ++;


name[i] = "Cisco WVC54GCA network camera";
server[i] = "thttpd/";
url[i] = "/main.cgi?next_file=index_in.htm";
body[i] = 'span class="model" style="position:relative;top:-12px">WVC54GCA</span>';
i++;

name[i] = "Cisco WVC54GCA network camera";
server[i] = "Apache/";
url[i] = "/img/main.cgi?next_file=main.htm";
body[i] = '<span class="model" style="position:relative;top:-12px">WVC54GCA</span>';
i++;

name[i] = "LevelOne IP Network Camera";
server[i] = "thttpd/";
url[i] = "/img/main.cgi?next_file=main.htm";
body[i] = 'id="NetCamPlayerWeb11g1"';
i++;

name[i] = "Linksys Wireless-G PTZ network camera";
url[i] = "/main.cgi?next_file=main.htm";
body[i] = 'Linksys Wireless-G PTZ ';
i++;

name[i] = "eyeMax DVR";
server[i] = "OwnServer1.0";
url[i] = "/login.html";
title[i] = "DVR System";
body[i] = "<object id='WebClient' classid='CLSID:9A74E90C-0233-4E1F-8EA1-105991C6FA12'";
i ++;

name[i] = "Camtron IP Camera";
url[i] = "/view.html";
title[i] = "Video Surveillance";
body[i] = '<object classid="CLSID:DD01C8CA-5DA0-4b01-9603-B7194E561D32" name="Tvs"';
i ++;

name[i] = "Viola DVR";
server[i] = "Boa/";
url[i] = "/ie.htm";
title[i] = "IE-Plugin";
body[i] = '<object classid="clsid:8C743238-AA51-42bd-875F-EE65526DFA1C" id="IE_OCX"';
i ++;

name[i] = "Foscam IP Camera";
server[i] = "Netwave IP Camera";
url[i] = "/ptz.htm";
body[i] = 'next_url=ptz.htm&ptz_center_onstart=';
i ++;

name[i] = "Hikvision Digital Video Server";
server[i] = "WindWeb/";
url[i] = "/";
title[i] = 'newocx';
body[i] = 'codebase="../codebase/NewHCNetActiveX.cab';
i ++;

n = i;

b = get_http_banner(port: port);
banner = egrep(string: b, pattern: "^Server:");

prev_url = NULL; prev_data = NULL;

for (i = 0; i < n; i ++)
{
 # nb: 'banner' is actually the Server response header.

 # If there's no Server response header...
 if (strlen(banner) == 0)
 {
   # ignore it if the signature expects one.
   if (
     (!isnull(server[i]) && strlen(server[i]) > 0) ||
     (!isnull(server_re[i]) && strlen(server_re[i]) > 0)
   ) continue;
 }
 else
 {
   # An empty server[i] means that we want *no* Server field
   if (!isnull(server[i]) && server[i] == "") continue;

   if (strlen(server[i]) > 0 && server[i] >!< banner) continue;
   if (strlen(server_re[i]) > 0 &&
       ! ereg(string: banner, pattern: "^Server: *"+server_re[i]+'[\r\n]*$'))
     continue;
 }

 if (strlen(url[i]) == 0 && (title[i] || title_re[i]))
 {
  url[i] = "/";
 }
 if (url[i])
 {
   if (url[i] == prev_url && strlen(prev_data) > 0)
     r = prev_data;
   else
   {
     t = http_send_recv3(port: port,
	  method:"GET",
   	  item:url[i]);


      if ( ! isnull(t) ) r = t[0] + t[1] + '\r\n'+ t[2];
      else r = NULL;
      prev_url = url[i];
      prev_data = r;
      if (isnull(r)) continue;	# Could not connect
    }

   if (strlen(banner) == 0)
   {
     s2 = egrep(string: r, pattern: "^Server:");
     if (strlen(server[i]) > 0 && server[i] >!< s2) continue;
     if (strlen(server_re[i]) > 0 &&
         ! ereg(string: s2, pattern: "^Server: *"+server_re[i]+'[\r\n]*$'))
       continue;
   }
   if (strlen(realm[i]) > 0 &&
       ! egrep(string: r,
       	 	pattern: '^WWW-Authenticate: *Basic +realm="' + realm[i] + '"[ \t\r\n]*') )
      continue;

   r = str_replace(string: r, find: '\r', replace: '\n');
   t = egrep(string: r, pattern: "<title>.*</title>", icase: 1);
   # In handwritten HTML, the title may be split on several lines
   # But as those gizmos are embedded servers, there is no risk AFAIK
   # But Active WebCam did it :-(
   if (strlen(t) == 0)
   {
    r2 = str_replace(string: r, find: '\n', replace: '');
    t = egrep(string: r2, pattern: "<title>.*</title>", icase: 1);
   }
   t = ereg_replace(string: t,
    pattern: '.*<title> *(.*[^ ]) *</title>.*',
      icase: 1, replace: "\1");
   if (strlen(title[i]) > 0 && t != title[i]) continue;
   if (strlen(title_re[i]) > 0 &&
      ! ereg(string: t, pattern: "^"+title_re[i]+"$")) continue;
   if (strlen(body_re[i]) > 0 &&
      ! egrep(string: r, pattern: body_re[i])) continue;
   if (strlen(body[i]) > 0 && body[i] >!< r) continue;
  }
 #
 security_note(port: port, extra: '\n'+name[i]);
 set_kb_item(name: 'www/'+port+'/webcam', value: name[i]);
 if (COMMAND_LINE) display(name[i], '\n');
 break;
}

# clean up if necessary
