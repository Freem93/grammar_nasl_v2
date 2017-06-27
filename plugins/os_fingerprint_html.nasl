#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35779);
  script_version("$Revision: 1.132 $");
  script_cvs_date("$Date: 2017/03/13 21:17:23 $");

  script_name(english:"OS Identification : HTML");
  script_summary(english:"Identifies devices based on HTML output.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server can be used to identify the host's operating
system.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to identify the remote operating system by examining
the HTML returned from certain HTTP requests.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("httpver.nasl");
  script_require_ports("Services/www");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = get_kb_list("Services/www");
if (isnull(ports))
  exit(0, "No web server was detected.");

ports = make_list(ports);
default_confidence = 100;
default_dev_type   = "embedded";

# Variables for each device:
#
# nb: for the arrays, *all* elements must be found for a match to occur.
# name		description of the device
# confidence    confidence level
# dev_type      type of the device (eg, embedded, printer, etc).
# port_re       regex for port at which to look
# url		page to examine
# server	string found in Server response header (may be "" if there is *no* such header)
# server_re	idem, regex
# headers       array of strings found in HTTP response headers
# headers_re	array of regexes to match against the headers
# title		array of strings found in title
# title_re      array of regexes to match against the title
# body          array of strings found in body
# body_re	array of regexes to match against the body.

i = 0;
name       = make_array();
confidence = make_array();
dev_type   = make_array();
port_re    = make_array();
url        = make_array();
server     = make_array();
server_re  = make_array();
headers    = make_array();
headers_re = make_array();
title      = make_array();
title_re   = make_array();
body       = make_array();
body_re    = make_array();
redir      = make_array();

name[i]       = "Android";
dev_type[i]   = "mobile";
url[i]        = "/";
server_re[i]  = "Swift[0-9]+\.[0-9]+";
headers_re[i] = make_list(
                  '^Location: +.+/www/index\\.html'
                );
i++;

name[i]       = "Aerohive HiveOS";
dev_type[i]   = "embedded";
url[i]        = "/";
title_re[i]   = make_list(
                  "^Aerohive HiveUI$"
                );
body_re[i]     = make_list(
                  '<td class="hm_version" .+>([0-9]+\\.[^<]+)<',
                  '<td class="hm_logo" .+>Hive.+OS<'
                );
i++;

name[i]       = "Avocent MergePoint Unity KVM switch";
dev_type[i]   = "switch";
url[i]        = "/login.php";
title_re[i]   = make_list(
                  "^MPU[0-9]+E? Explorer"
                );
body_re[i]     = make_list(
                  "Avocent, the Avocent logo, MergePoint Unity",
                  "<b>Appliance firmware version [0-9]+(\.[0-9]+)+</b>"
                );
i++;

name[i]       = "AXIS Network Document Server";
confidence[i] = 85;
dev_type[i]   = "embedded";    # 'scanner'?
url[i]        = "/this_server/all_settings.shtml";
title_re[i]   = make_list(
                  "^Settings List"
                );
body_re[i]     = make_list(
                  'This AXIS ([0-9][^ ]+) Settings List',
                  'var aWindow = window.+this_server/config_ini\\.shtml',
                  'PaperSize0'
                );
i++;

name[i]       = "AXIS Print Server";
confidence[i] = 85;
dev_type[i]   = "printer";
port_re[i]    = "^(80|631)$";
url[i]        = "/";
title_re[i]   = make_list(
                  "^Network Print Server"
                );
body_re[i]     = make_list(
                  'WARNING: Contact with the print server will be lost a while, during the restart',
                  '<td>&nbsp;&nbsp;<b>AXIS [0-9][^ ]+</b></td>'
                );
i++;

name[i]       = "Belkin Wireless G Plus MIMO Router";
dev_type[i]   = "wireless-access-point";
url[i]        = "/";
title_re[i]   = make_list(
                  "^Belkin Wireless G Plus MIMO Router"
                );
body[i]       = make_list(
                  '<FRAME SRC="/status.htm" NAME="main"'
                );
i++;

name[i]       = "Blue Coat PacketShaper";
dev_type[i]   = "embedded";
url[i]        = "/login.htm";
server[i]     = "httpd/1.";
title_re[i]   = make_list(
                  "PacketShaper Login$"
                );
body_re[i]    = make_list(
                  '(alt="Blue Coat Systems logo"|Blue Coat Systems, Inc\\. All rights reserved\\.)'
                );
i++;

# nb: there are two fingerprints for imageRUNNER printers.
name[i]       = "Canon imageRUNNER Printer";
dev_type[i]   = "printer";
port_re[i]    = "^80$";
url[i]        = "/";
server[i]     = "CANON HTTP Server";
headers_re[i] = make_list(
                  '<META http-equiv=Refresh content="0; URL=http.+:8000/rps/"'
                );
i++;

name[i]       = "Canon imageRUNNER Printer";
dev_type[i]   = "printer";
port_re[i]    = "^80$";
url[i]        = "/";
server[i]     = "CANON HTTP Server";
body[i]       = make_list(
                  "function goto_country(){",
                  "\./twelcome\.cgi\?CorePGTAG"
                );
i++;

name[i]       = "Canon PIXMA Printer";
dev_type[i]   = "printer";
port_re[i]    = "^80$";
url[i]        = "/English/pages_MacUS/index.html";
server[i]     = "KS_HTTP/";
body[i]       = make_list(
                  "<title>Canon [A-Za-z0-9\-]+ series Network Configuration \| Basic Information</title>",
                  "Link Quality:</th>"
                );

i++;

name[i]       = "Check Point GAiA";
confidence[i] = 80;
dev_type[i]   = "firewall";
url[i]        = "/";
server[i]     = "CPWS";
body[i]       = make_list(
                  'content="WEBUI LOGIN PAGE"',
                  "var version='R",
                  'var formAction="/cgi-bin/home.tcl:'
                );
i++;

# nb: this web server should be flagged also as "Service/cp_ica" by
#     checkpoint_ica_detect.nasl.
name[i]       = "Check Point GAiA";
confidence[i] = 70;
dev_type[i]   = "firewall";
url[i]        = "/";
server[i]     = "Check Point";
title[i]      = make_list(
                  'Check Point Certificate Services'
                );
body[i]       = make_list(
                  "window.status='Install this CA certification path'"
                );
i++;

# nb: Cisco distributes this as either a dedicated server with RHEL
#     or an OVA. Confidence is low since we can't distinguish between
#     them with just this fingerprint.
name[i]       = "CISCO Application Networking Manager (ANM)";
confidence[i] = 70;
dev_type[i]   = "embedded";
url[i]        = "/";
server[i]     = "Jetty/";
title_re[i]   = make_list(
                  "^ANM - Login$"
                );
body_re[i]    = make_list(
                  '<div class="cuesLoginProductName">Application Networking Manager</div>',
                  'src="/cues_images/cisco_logo_header.png" align="absmiddle" title="Cisco" alt="Cisco"/>'
                );
i++;

name[i]       = "CISCO IP Telephone 7937G";
url[i]        = "/localmenus.cgi?func=604";
server[i]     = "Rockpile Web Server";
body[i]       = make_list(
                  "<CiscoIPPhoneIconMenu>"
                );
body_re[i]    = make_list(
                  '<Name>: +Cisco IP Phone 7937G, Global</Name>'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO IP Telephone 7941G";
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager";
title[i]      = make_list(
                  "Cisco Systems, Inc."
                );
body[i]       = make_list(
                  '<font color="#FFFFFF" size="4">Cisco Unified IP Phone CP-7941G'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO IP Telephone 7960";
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager";
title[i]      = make_list(
                  "Cisco Systems, Inc."
                );
body_re[i]    = make_list(
                  '<font color="#FFFFFF" size="4">(Cisco|Cisco Systems, Inc\\.) IP Phone 7960 \\( SEP'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO IP Telephone 7971G";
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager";
title[i]      = make_list(
                  "Cisco Systems, Inc."
                );
body[i]       = make_list(
                  '<font color="#FFFFFF" size="4">Cisco Unified IP Phone CP-7971G'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO IP Telephone CP-8851";
url[i]        = "/";
# No server header for this model
title[i]      = make_list(
                  "Cisco Systems, Inc."
                );
body[i]       = make_list(
                  '<font color="#FFFFFF" size="4">Cisco IP Phone CP-8851'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO Unified IP Telephone CP-8831";
url[i]        = "/";
# No server header for this model
title[i]      = make_list(
                  "Cisco Systems, Inc."
                );
body[i]       = make_list(
                  '<font color="#FFFFFF" size="4">Cisco Unified IP Phone CP-8831'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO IP Telephone 7910";
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager";
title[i]      = make_list(
                  "Cisco Systems, Inc."
                );
body_re[i]    = make_list(
                  '<font color="#FFFFFF" size="4">(Cisco|Cisco Systems, Inc\\.) IP Phone (CP-)?7910G? \\( SEP'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO IP Telephone 7911";
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager";
title[i]      = make_list(
                  "Cisco Systems, Inc."
                );
body_re[i]    = make_list(
                  '<font color="#FFFFFF" size="4">(Cisco|Cisco Systems, Inc\\.) Unified IP Phone (CP-)?7911G? \\( SEP'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO IP Telephone 7940";
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager";
title[i]      = make_list(
                  "Cisco Systems, Inc."
                );
body_re[i]    = make_list(
                  '<font color="#FFFFFF" size="4">(Cisco|Cisco Systems, Inc\\.) IP Phone (CP-)?7940G? \\( SEP'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO IP Telephone 7960G";
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager";
title[i]      = make_list(
                  "Cisco Systems, Inc."
                );
body_re[i]    = make_list(
                  '<font color="#FFFFFF" size="4">(Cisco|Cisco Systems, Inc\\.) IP Phone (CP-)?7960G \\( SEP'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO Unified IP Telephone 7961G";
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager";
title[i]      = make_list(
                  "Cisco Systems, Inc."
                );
body_re[i]    = make_list(
                  '<font color="#FFFFFF" size="4">(Cisco|Cisco Systems, Inc\\.) Unified IP Phone (CP-)?7961G \\( SEP'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO Unified IP Telephone 7962G";
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager";
title[i]      = make_list(
                  "Cisco Systems, Inc."
                );
body_re[i]    = make_list(
                  '<font color="#FFFFFF" size="4">(Cisco|Cisco Systems, Inc\\.) Unified IP Phone (CP-)?7962G \\( SEP'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO ATA";
port_re[i]    = "^80$";
url[i]        = "/";
title[i]      = make_list(
                  "Login Page"
                );
body_re[i]    = make_list(
                  '<TD class=APPNAME>Phone Adapter Configuration Utility</TD>'
                );
i++;

# generic catch-all for Cisco IP Telephones
# Several servers used
name[i]       = "CISCO IP Telephone";
port_re[i]    = "^80$";
url[i]        = "/";
title[i]      = make_list(
                  "Cisco Systems, Inc."
                );
body_re[i]    = make_list(
                  '<font color="#FFFFFF" size="4">(Cisco|Cisco Systems, Inc\\.)( Unified)? IP Phone ([A-Z]+-)?[0-9]+[A-Z]?'
                );
redir[i]      = 1;
i++;

name[i]       = "CISCO IPS";
confidence[i] = 85;
url[i]        = "/idm/index.html";
server[i]     = "HTTP/1.1 compliant";
title[i]      = make_list(
                  "IPS Device Manager"
                );
body[i]       = make_list(
                  'Cisco IPS devices'
                );
i++;

name[i]       = "CISCO Network Analysis Module (NAM)";                  # old versions, circa 2001
dev_type[i]   = "embedded";
url[i]        = "/";
title_re[i]   = make_list(
                  "^NAM Web Manager$"
                );
body_re[i]    = make_list(
                  "Divva Home Page\..+This page just redirects",
                  "Copyright \(c\) .+ by cisco Systems, Inc\."
                );
i++;

name[i]       = "CISCO Network Analysis Module (NAM)";
dev_type[i]   = "embedded";
url[i]        = "/authenticate/login";
title_re[i]   = make_list(
                  "^NAM Login$"
                );
body_re[i]    = make_list(
                  "productName='Network Analysis Module'",
                  "(Cisco reserves the right|Cisco will not have any liability)"
                );
i++;

name[i]       = "Cisco NX-OS";
dev_type[i]   = "switch";
url[i]        = "/";
title_re[i]   = make_list(
                  "^Cisco Nexus [0-9]+[a-zA-Z]*$"
                );
body_re[i]    = make_list(
                  "<h1>Cisco Nexus [0-9]+[a-zA-Z]*</h1>",
                  '<a href="http://www\\.cisco\\.com/go/nexus[0-9]+[a-zA-Z]*">'
                );
i++;

name[i]       = "Cisco PAP2T Phone Adapter";
port_re[i]    = "^80$";
url[i]        = "/index.html";
title[i]      = make_list(
                  "Linksys PAP2 Configuration"
                );
body[i]       = make_list(
                  '<td>Product Name:<td><font color="darkblue">PAP2T<'
                );
i++;

name[i]       = "CISCO VPN Concentrator";
dev_type[i]   = "VPN";
confidence[i] = 85;
port_re[i]    = "^(80|443)$";
url[i]        = "/admin.html";
server[i]     = "Web Server";
title_re[i]   = make_list(
                  "^Cisco Systems, Inc\. VPN [0-9].+ Concentrator"
                );
body_re[i]    = make_list(
                  '<h2>VPN [0-9].+ Concentrator</h2>'
                );
i++;

name[i]       = "CISCO";
dev_type[i]   = "router";
confidence[i] = 66;
port_re[i]    = "^(80|443)$";
url[i]        = "/";
server[i]     = "";
headers[i]    = make_list(
                  'Expires:',
                  'WWW-Authenticate: Basic realm="level 15 access"'
                );
body[i]       = make_list(
                  '<H1>Authorization Required</H1>Browser not authentication-capable or authentication failed.</BODY>'
                );
i++;

name[i]       = "Citrix NetScaler";
dev_type[i]   = "embedded";
url[i]        = "/";
title_re[i]   = make_list(
                  "^Citrix Login$"
                );
body_re[i]    = make_list(
                  '<form name="form1" action="/login/do_login"',
                  '<td class="ns_login_header">'
                );
i++;

name[i]       = "Corero TopLayer IPS";
dev_type[i]   = "embedded";
confidence[i] = 85;
url[i]        = "/";
title[i]      = make_list(
                  "^IPS Management Application$"
                );
body[i]       = make_list(
                  '<img src="index_page_ips.png"',
                  '<area href="/jaws/ips/ips.jnl"'
                );
i++;

name[i]       = "D-Link ShareCenter";
confidence[i] = 85;
dev_type[i]   = "embedded";
url[i]        = "/";
server[i]     = "Server: lighttpd/";
body[i]       = make_list(
                  '//Text:In order to access the ShareCenter, ',
                  '<form name="form" id="form" method="post" action="/cgi-bin/login_mgr.cgi">'
                );
i++;

name[i]       = "Dell iDRAC 6";
dev_type[i]   = "embedded";
confidence[i] = 85;
url[i]        = "/dellUI/login.htm";
server[i]     = "lighttpd/";
body[i]       = make_list(
                  'top.location.href = "/Applications/dellUI/login.htm";',
                  'alt="Integrated Dell Remote Access Controller" title="iDRAC6 Enterprise"'
                );
i++;

name[i]       = "Dell Laser Printer";
dev_type[i]   = "printer";
port_re[i]    = "^80$";
url[i]        = "/";
server[i]     = "EWS-NIC4/";
title[i]      = make_list(
                  "Dell MFP Laser"
                );
i++;

name[i]       = "Eaton Powerware UPS with a ConnectUPS Web/SNMP Card";
dev_type[i]   = "embedded";
confidence[i] = 95;
server[i]     = "UPS_Server/";
url[i]        = "/PSummary.html";       # nb: /rss2.xml could be a useful alternative page
body[i]       = make_list(
                  '<form name=PSummary action=',
                  '>UPS Model<',
                  '>POWERWARE ',
                  '>ConnectUSP Web/SNMP Card'
                );
i++;

name[i]       = "EMC CLARiiON";
dev_type[i]   = "embedded";
url[i]        = "/start.js";
body[i]       = make_list(
                  'var _naviVersion =',
                  'code="com.emc.navisphere'
                );
i++;

name[i]       = "EMC Data Domain OS";
server[i]     = "Apache";
dev_type[i]   = "embedded";
url[i]        = "/ddem/";
title_re[i]   = make_list(
                  "^Enterprise Manager$"
                );
body[i]       = make_list(
                  '<!-- title>DataDomain Enterprise Manager</title -->'
                );
i++;

name[i]       = "Emerson Industrial Automation SM-Ethernet Drive Controller";
confidence[i] = 80;
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager/";
title[i]      = make_list("Drive Description");
body[i]       = make_list(
                  'Emerson',
                  'SM-Ethernet'
                );
i++;

name[i]       = "EPSON Stylus Printer";
dev_type[i]   = "printer";
port_re[i]    = "^80$";
url[i]        = "/";
server[i]     = "EPSON_Linux UPnP/";
title[i]      = make_list(
                  "Epson Stylus"
                );
i++;

name[i]       = "EulerOS";
url[i]        = "/";
server[i]     = "Apache/";
title[i]      = make_list(
                  "Test Page for the Apache HTTP Server on EulerOS Linux"
                );
body[i]       = make_list(
                  "For information on EulerOS Linux,",
                  "<h1>EulerOS Linux "
                );
dev_type[i]   = "general-purpose";
confidence[i] = 80;
i++;

name[i]       = "ExtremeXOS Network Operating System";
url[i]        = "/";
server[i]     = "XOS ";
title[i]      = make_list(
                  "ExtremeXOS ScreenPlay&#174;"
                );
body[i]       = make_list(
                  "/com/extremenetworks/"
                );
i++;

name[i]       = "F5 Networks BIG-IP";
dev_type[i]   = "load-balancer";
url[i]        = "/tmui/";
headers_re[i] = make_list(
                  '^401 F5 Authorization Required',
                  '^WWW-Authenticate: +Basic realm="BIG-IP"'
                );
i++;

name[i]       = "F5 Networks BIG-IQ";
dev_type[i]   = "embedded";
url[i]        = "/";
title_re[i]   = make_list(
                  "BIG-IQ&trade;- Redirect"
                );
body_re[i]    = make_list(
                  '<meta name="Copyright" content="Copyright \\(c\\) [^ ]+, F5 Networks, Inc'
                );
i++;

name[i]       = "FireEye OS";
dev_type[i]   = "embedded";
url[i]        = "/";
title_re[i]   = make_list(
                  "FireEye - Please Log In"
                );
body_re[i]    = make_list(
                  '<link href="\\/stylesheets\\/templates\\/fireeye\\/',
                  "&copy; Copyright .* FireEye, Inc\. All rights reserved\."
                );
i++;

name[i]       = "FortiOS on Fortinet FortiGate";
dev_type[i]   = "firewall";
url[i]        = "/login";
body[i]       = make_list(
                  'if (window.opener) {window.opener.top.location.reload(); self.close();}',
                  '>Warning: this page requires Javascript. To correctly view, please enable it',
                  'str_table.lockout_msg = "Too many login failures. Please try again in a few minutes...";'
                );
i++;

name[i]       = "HDHomeRun Networked Digital TV Tuner";
port_re[i]    = "^80$";
url[i]        = "/";
server[i]     = "UPnP/";
title[i]      = make_list(
                  "HDHomeRun"
                );
body[i]       = make_list(
                  "Silicondust HDHomeRun&#8482;"
                );
body_re[i]    = make_list(
                  '<div class="S">Device ID: [0-9A-Fa-f]+<br',
                  'Firmware: [0-9]+'
                );
i++;

name[i]       = "Hikvision Digital Video Server";
dev_type[i]   = "camera";
url[i]        = "/";
server[i]     = "WindWeb/";
title_re[i]   = make_list(
                  "^newocx$"
                );
body[i]       = make_list(
                  'name=activex ><WINDWEB_URL>',
                  'codebase="../codebase/NewHCNetActiveX.cab'
                );
i++;

name[i]       = "Hitachi Projector";
dev_type[i]   = "embedded";
port_re[i]    = "^80$";
url[i]        = "/index.html";
server[i]     = "Allegro-Software-RomPager/";
title_re[i]   = make_list(
                  '^Logon$'
                );
body[i]       = make_list(
                  '<script src="/FS/FLASH0/prj0B02.js',
                  'enable JavaScript in order to use the projector web pages',
                  'str = ProjectorNameAnalyze(str)',
                  '>PIN Lock & Transition Detector'
                );
i++;

name[i]       = "HP LaserJet";
dev_type[i]   = "printer";
url[i]        = "/";
server_re[i]  = "(HP-Chai(SOE|Server)|Virata-EmWeb)/";
body_re[i]    = make_list(
                  "(/hp/device/this.LCDispatcher|<title> HP Color LaserJet)"
                );
i++;

name[i]       = "HP LaserJet";
dev_type[i]   = "printer";
url[i]        = "/";
server[i]     = "Server: $ProjectRevision: ";
title[i]      = make_list(
                  "HP LaserJet"
                );
body[i]       = make_list(
                  '<td><div class="mastheadPhoto"><img src="/Images/masthead.jpg" alt="Printer Cartridges">'
                );
i++;

name[i]       = "HP Integrated Lights Out";
dev_type[i]   = "embedded";
url[i]        = "/";
body_re[i]    = make_list(
                  "Copyright .+ Hewlett-Packard Development Company",
                  # nb: the title is combined in the regex here because
                  #     older iLO boards didn't have it.
                  '(If you are communicating with iLO|<title>iLO [0-9]+</title>|SetCookie\\("hp-iLO-Login"|Note: 128-bit SSL is required to access iLO\\.)'
                );
i++;

# nb: http://en.wikipedia.org/wiki/Guardian_Service_Processor
name[i]       = "HP Guardian Service Processor";
confidence[i] = 75;
dev_type[i]   = "general-purpose";
url[i]        = "/";
title[i]      = make_list(
                  'HP Web Console on'
                );
body[i]       = make_list(
                  '<APPLET CODE="pericom/TeemWorld/TeemWorld.class" ARCHIVE="TeemWorld.jar" ',
                  '<PARAM NAME=IPAddress',
                  '<PARAM NAME=SubTitle   VALUE = "Hewlett Packard">'
                );
i++;

# nb: there are several different signatures for ProCurve switches.
name[i]       = "HP Switch";
confidence[i] = 75;
dev_type[i]   = "switch";
server[i]     = "eHTTP v";
url[i]        = "/";
title[i]      = make_list(
                  "ProCurve Switch"
                );
i++;

name[i]       = "HP Switch";
confidence[i] = 75;
dev_type[i]   = "switch";
server[i]     = "eHTTP v";
url[i]        = "/banner.html";
title[i]      = make_list(
                  "Notice to users"
                );
body[i]       = make_list(
                  "Please register your products now at:",
                  "www.ProCurve.com"
                );
i++;

name[i]       = "HP Switch";
confidence[i] = 75;
dev_type[i]   = "switch";
server[i]     = "eHTTP v";
url[i]        = "/html/nhome.html";
title[i]      = make_list(
                  "HP Switch "
                );
body[i]       = make_list(
                  '<div class="procurvelogo">'
                );
i++;

name[i]       = "IBM BNT";
dev_type[i]   = "switch";
url[i]        = "/";
server[i]     = "Agranat-EmWeb";
title[i]      = make_list(
                  "Login to IBM Networking Operating System RackSwitch"
                );
body[i]       = make_list(
                  '<TD><H1><CENTER>&nbsp;<FONT color="#666699">Login to</FONT></CENTER>',
                  '<FORM METHOD=POST NAME=loginForm ACTION="/login.html/bar">',
                  '<INPUT NAME="username" id="username" TYPE="text" onfocus="this.form.username.value='
                );
i++;

name[i]       = "IBM Global Console Manager GCM16 KVM";
dev_type[i]   = "embedded";
url[i]        = "/login.php";
server[i]     = "AEWS/";
title_re[i]   = make_list(
                  "^GCM16 Explorer$"
                );
body[i]       = make_list(
                  "<form method='post' action='/login.php' class='form-block'>"
                );
i++;

name[i]       = "IBM Global Console Manager GCM32 KVM";
dev_type[i]   = "embedded";
url[i]        = "/login.php";
server[i]     = "AEWS/";
title_re[i]   = make_list(
                  "^GCM32 Explorer$"
                );
body[i]       = make_list(
                  "<form method='post' action='/login.php' class='form-block'>"
                );
i++;

name[i]       = "Infoblox NetMRI";
dev_type[i]   = "embedded";
confidence[i] = 75;
url[i]        = "/netmri/config/userAdmin/login.tdf";
title[i]      = make_list(
                  "JavaScript required"
                );
body[i]       = make_list(
                  'action="/netmri/config/userAdmin/login.tdf"',
                  '<input type=hidden name=mode value="LOGIN-FORM"'
                );
i++;

name[i]       = "IP Power 9258";
dev_type[i]   = "embedded";
url[i]        = "/";
title_re[i]   = make_list(
                  '^IP9258$'
                );
body[i]       = make_list(
                  '<form NAME="login" ACTION="/tgi/login.tgi"',
                  '<b>IP9258 Login</b>'
                );
i++;

name[i]       = "Konica Minolta Digital Copier/Printer";
dev_type[i]   = "printer";
url[i]        = "/";
title[i]      = make_list(
                  "KONICA MINOLTA PageScope Web Connection for magicolor"
                );
i++;

name[i]       = "KYOCERA Printer";
dev_type[i]   = "printer";
url[i]        = "/start/start.htm";
server[i]     = "KM-MFP-http/V";
body[i]       = make_list(
                  'Kyocera Command Center',
                  '<!--The title is the model name read from the printer ***-->'
                );
i++;

name[i]       = "KYOCERA Printer";
dev_type[i]   = "printer";
url[i]        = "/";
server[i]     = "KM-MFP-http/V";
body[i]       = make_list(
                  '<frame name=wlmframe  src="/startwlm/Start_Wlm.htm"'
                );
i++;

name[i]       = "Lantronix Universal Device Server UDS1100";
dev_type[i]   = "embedded";
confidence[i] = 80;
url[i]        = "/";
body[i]       = make_list(
                  '<meta http-equiv="refresh" content="1; URL=secure/ltx_conf.htm">',
                  'function doRedirect() {'
                );
i++;

# nb: The banner reports the server as Apache, but other (non-existent?)
#     pages return a different Server response header.
name[i]       = "Mandiant Intelligent Response appliance";
url[i]        = "/index.asp";
server[i]     = "MIR";
headers[i]    = make_list(
                  '^WWW-Authenticate: basic realm="MIR Realm"'
                );
body[i]       = make_list(
                  'You are not authorized to access this resource.'
                );
i++;

name[i]       = "McAfee Web Gateway";
confidence[i] = 85;
dev_type[i]   = "embedded";
url[i]        = "/Konfigurator/request";
server[i]     = "Server: mwg-ui";
title[i]      = make_list(
                  '^McAfee | Web Gateway - '
                );
body[i]       = make_list(
                  'loginform',
                  '/Konfigurator/images/tab-bar-logo.gif" align="top">'
                );
i++;

name[i]       = "MikroTik RouterOS";
url[i]        = "/";
body[i]       = make_list(
                  '<h1>RouterOS v',
                  'You have connected to a router. Administrative access only.',
                  '>&copy; mikrotik<'
                );
i++;

name[i]       = "MikroTik RouterOS";     # nb: 4.x and older
url[i]        = "/";
body_re[i]    = make_list(
                  '>mikrotik routeros [0-9].+ configuration page<'
                );
i++;

name[i]       = "NetBotz Monitoring Appliance";
dev_type[i]   = "embedded";
url[i]        = "/";
title_re[i]   = make_list(
                  '^NetBotz Network Monitoring Appliance'
                );
body[i]       = make_list(
                  '<frame src="statusHeader.html"',
                  '<frame src="crawlerLogin.html"'
                );
i++;

name[i]       = "NETGEAR FVS318N ProSafe Wireless-N VPN Firewall";
dev_type[i]   = "wireless-access-point";
url[i]        = "/scgi-bin/platform.cgi";
title[i]      = make_list(
                  "NETGEAR Configuration Manager Login"
                );
body_re[i]    = make_list(
                  'NETGEAR ProSafe.+ VPN Firewall FVS318N'
                );
i++;

name[i]       = "Nortel Meridian Integrated RAN (MIRAN)";
confidence[i] = 80;
dev_type[i]   = "embedded";
url[i]        = "/"+SCRIPT_NAME;
server[i]     = "WindWeb/";
body[i]       = make_list(
                  'Please mail problems to <a href="mailto:.+@nortelnetworks".+Miran BUI Development'
                );
i++;

name[i]       = "OpenBSD";
dev_type[i]   = "general-purpose";
url[i]        = "/";
title[i]      = make_list(
                  'Test Page for Apache Installation'
                );
body[i]       = make_list(
                  '<img src="openbsd_pb.gif" alt="[Powered by OpenBSD]">'
                );
i++;

name[i]       = "QNAP QTS on a TS-Series NAS";
dev_type[i]   = "embedded";
url[i]        = "/cgi-bin";
server[i]     = "http server ";
title[i]      = make_list(
                  "QNAP Turbo NAS"
                );
body[i]       = make_list(
                  'QNAP.QOS.user = {'
                );
i++;

name[i]       = "Secure Mail (IronMail) Appliance";
dev_type[i]   = "embedded";
url[i]        = "/admin/login.do";
title_re[i]   = make_list(
                  '(Secure Computing|IronMail&reg;)'
                );
body[i]       = make_list(
                  '<form name="LoginForm" method="post" action="/admin/auth.do',
                  '<div class="loginProductName">'
                );
i++;

# nb: there are two entries for Juniper SSL VPN Appliance.
name[i]       = "Juniper SSL VPN Appliance";
port_re[i]    = "^443$";
url[i]        = "/";
title[i]      = make_list(
                  "Secure&#32;Access&#32;SSL&#32;VPN"
                );
body_re[i]    = make_list(
                  '<div>Copyright &copy; 2[0-9]+-2[0-9]+ Juniper Networks, Inc\\.</div>',
                  '/dana-na/(auth|auth/url_admin|auth/url_default)/welcome\\.cgi'
                );
i++;

name[i]       = "Juniper SSL VPN Appliance";
confidence[i] = 71;
port_re[i]    = "^443$";
url[i]        = "/"+SCRIPT_NAME;
server[i]     = "";
headers_re[i] = make_list(
                  '^Location: +.+/dana-na/auth/welcome\\.cgi',
                  '^Set-Cookie: DSLaunchURL='
                );
i++;

name[i]       = "KYOCERA Print Server";
dev_type[i]   = "printer";
port_re[i]    = "^80$";
url[i]        = "/links_en.html";
body[i]       = make_list(
                  'kyocera',
                  '/status/pport_en.html'
                );
i++;

name[i]       = "PCoIP Zero Client";
confidence[i] =  80;
dev_type[i]   = "embedded";
url[i]        = "/login.html";
server[i]     = "Server: $ProjectRevision: ";
title[i]      = make_list(
                  "Log In"
                );
body[i]       = make_list(
                  '<h4>PCoIP&#174 Zero Client</h4>'
                );
i++;

name[i]       = "Pitney Bowes Digital Mailing System";
confidence[i] = 65;
dev_type[i]   = "embedded";
url[i]        = "/en/main.js";
body[i]       = make_list(
                  '"./public/stat/sysst_indx.htm"',
                  '"./private/mainte/firm_up_indx.htm",',
                  'window.open("../../help/help_"+dir+"_indx.htm?id="+id+"&sub="+sub,"");'
                );
i++;

name[i]       = "Riverbed Optimization System (RiOS) on a Riverbed SteelHead";
confidence[i] = 75;
dev_type[i]   = "embedded";
url[i]        = "/mgmt/login?dest=%2Fmgmt%2Fgui%3Fp%3Dhome&reason=&username=";
body_re[i]    = make_list(
                  '<p class="announcement">Riverbed Steel[Hh]ead',
                  'src="/images/poweredby.gif" alt="Powered by RiOS&trade;"'
                );
i++;

name[i]       = "Samsung Data Management Server";   # v1.x
dev_type[i]   = "scada";
url[i]        = "/";
title[i]      = make_list(
                  "Samsung Data Management Server"
                );
body[i]       = make_list(
                  'com.samsung.dms.checkjre.CheckJRE'
                );
i++;

name[i]       = "Samsung Data Management Server";   # v2.x
dev_type[i]   = "scada";
url[i]        = "/dms2/Login.jsp";
title[i]      = make_list(
                  "Samsung Data Management Server"
                );
body[i]       = make_list(
                  '>LOGIN Data Management Server<'
                );
i++;

name[i]       = "SCO OpenServer";
url[i]        = "/dochome.html";
server[i]     = "NCSA/";
title[i]      = make_list(
                  "SCO Documentation Library"
                );
body[i]       = make_list(
                  "/FEATS/CONTENTS.html>SCO OpenServer"
                );
i++;

name[i]       = "Sipura Analog Telephone Adapter";
port_re[i]    = "^80$";
url[i]        = "/";
server[i]     = "";
title[i]      = make_list(
                  "Sipura SPA Configuration"
                );
body[i]       = make_list(
                  ">Product Name:<"
                );
i++;

name[i]       = "SonicWALL SSL-VPN Appliance";
url[i]        = "/cgi-bin/welcome/VirtualOffice";
server[i]     = "SonicWALL SSL-VPN Web Server";
body[i]       = make_list(
                  "virtual office - Powered by SonicWALL"
                );
i++;

name[i]       = "AsyncOS";
url[i]        = "/login";
server_re[i]  = "glass/[0-9.]+ Python/[0-9.]+";
title_re[i]   = make_list(
                  "^IronPort [CMX][0-9]+"
                );
body_re[i]    = make_list(
                  'alt="IronPort (Spam|[CMX][0-9]+)'
                );
i++;

name[i]       = "D-Link Wireless Access Point";
dev_type[i]   = "wireless-access-point";
port_re[i]    = "^80$";
url[i]        = "/index.php";
title_re[i]   = make_list(
                  "^D-Link Corporation *\\| *[wW][iI][rR][eE][lL][eE][sS][sS] [aA][cC][cC][eE][sS][sS] [pP][oO][iI][nN][tT]"
                );
body[i]       = make_list(
                  'Login to the Access Point:'
                );
i++;

name[i]       = "CISCO ASA 5500";
port_re[i]    = "^443$";
url[i]        = "/+CSCOE+/win.js";
body_re[i]    = make_list( 'CSCO_WebVPN');
i++;

name[i]       = "Trend Micro InterScan Web Security Virtual Appliance";
port_re[i]    = "^1812$";
url[i]        = "/logon.jsp";
title[i]      = make_list(
                  "Trend Micro InterScan Web Security Virtual Appliance"
                );
body_re[i]    = make_list( '2[0-9]+ Trend Micro Incorporated. All rights reserved.</td>');
i++;

name[i]       = "Trimble GPS Receiver";
server_re[i]  = "^TRMB/[0-9]";
body[i]       = make_list(
                  'Trimble IP Enabled Geomatics GPS Receiver'
                );
i++;

name[i]       = "Trimble NetR5 Receiver";
server_re[i]  = "^TRMB/[0-9]";
body[i]       = make_list(
                  'GPSWeb Version',
                  'navigation.php?NoClientReload=1'
                );
i++;

name[i]       = "Juniper Junos";
confidence[i] = 85;
url[i]        = "/login";
title_re[i]   = make_list('Log In - Juniper (Web Device Manager|Networks Web Management)');
body_re[i]    = make_list('[0-9]+, Juniper Networks, Inc. *<a');
i++;

name[i]       = "Visara FEP-4600 Communications Controller";
url[i]        = "/";
title[i]      = make_list("Visara FEP4600");
body[i]       = make_list(
                  '<IMG SRC="/images/Administrative.jpg"></A>',
                  '<TD COLSPAN=2 ALIGN=CENTER>Software revision level: '
               );
i++;

name[i]       = "PowerLogic EGX100";
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager/";
headers_re[i] = make_list(
                  '^WWW-Authenticate: +Basic realm="EGX100"'
                );
i++;

name[i]       = "Printronix T 5000 Printer";
dev_type[i]   = "printer";
url[i]        = "/STATUS";
server[i]     = "Allegro-Software-RomPager/";
body[i]       = make_list(
                  'COT Interface Adapter System',
                  '<img src="cotlogo3d.gif"',
                  '<strong>Printronix T 5000</strong>'
                );
i++;

name[i]       = "Printronix Printer";
dev_type[i]   = "printer";
url[i]        = "/";
title[i]      = make_list("Integrated PrintNet Enterprise Home Page");
body[i]       = make_list(
                  '<legend>Welcome to Integrated PrintNet Enterprise</legend>',
                  '<label for="Configuration"><a href="indexConf.html" title="Configuration">Configuration</a></label>'
                );
i++;

name[i]       = "Samsung ML-2580N Series Printer";
dev_type[i]   = "printer";
url[i]        = "/home.htm";
body[i]       = make_list(
                  '<title>SWS - Home </title>";',
                  'var tray2Installed =',
                  'ML-2580N'
                );
i++;

name[i]       = "Samsung SCX-6545 Series Printer";
dev_type[i]   = "printer";
url[i]        = "/sws/data/sws_data.js";
body_re[i]    = make_list(
                  'SWS.DATA\\.modelName = "Samsung SCX-6545 Series";'
                );
i++;

name[i]       = "Samsung Printer";
dev_type[i]   = "printer";
url[i]        = "/";
title[i]      = make_list(
                  'SyncThru Web Service'
                );
body_re[i]    = make_list(
                  'var COPYRIGHT =.+ SAMSUNG\\. All rights reserved\\.";',
                  'function ChangeLocation\\(\\)'
                );
i++;

name[i]       = "SEW MOVIDRIVE";
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager/";
title[i]      = make_list(
                  'SEW - Movidrive'
                );
body[i]       = make_list(
                  '<frame name="BalkenHoriz"'
                );
i++;

name[i]       = "SINDOH D401 Printer";
dev_type[i]   = "printer";
url[i]        = "/wcd/system.xml";
body_re[i]    = make_list(
                  '<MFP><ScreenName>system_device</ScreenName>',
                  '<System><ProductName>SINDOH D401</ProductName>'
                );
i++;

name[i]       = "Toshiba e-Studio 5540C printer";
dev_type[i]   = "printer";
url[i]        = "/js/Device.js";
body[i]       = make_list(
                  '<ModelName>TOSHIBA e-STUDIO5540C</ModelName><Printer>'
                );
i++;

name[i]       = "Foscam IP Camera";
dev_type[i]   = "camera";
url[i]        = "/ptz.htm";
body[i]       = make_list(
                  'next_url=ptz.htm&ptz_center_onstart='
                );
i++;

name[i]       = "VBrick";
confidence[i] = 75;
dev_type[i]   = "embedded";
server[i]     = "Rapid Logic/";
url[i]        = "/";
title[i]      = make_list(
                  "VBrick Integrated Web Server (IWS) Login"
                );
body[i]       = make_list(
                  '<input type=text size=20 name=username ONKEYUP="nextField(event'
                );
i++;

name[i]       = "VMware ESXi";
dev_type[i]   = "hypervisor";
port_re[i]    = "^443$";
url[i]        = "/";
body[i]       = make_list(
                  '<meta name="description" content="VMware ESXi',
                  'document.write(ID_ESX_VIClientDesc);'
                );
i++;

name[i]       = "Wiesemann & Theis Web-Thermograph";
dev_type[i]   = "embedded";
url[i]        = "/";
title_re[i]   = make_list(
                  '^(Web-Thermo-Hygrograph|Web-IO Thermometer)'
                );
body[i]       = make_list(
                  'Ihr Browser unterst&uuml;tzt keine Frames'
                );
i++;

name[i]       = "Xerox ColorQube";
dev_type[i]   = "printer";
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager/";
title_re[i]   = make_list(
                  '^Home'
                );
body[i]       = make_list(
                  '<meta content="printer; embedded web server',
                  "Model=ColorQube",
                  "XEROX CORPORATION"
                );
i++;

name[i]       = "Xerox ColorQube";
dev_type[i]   = "printer";
url[i]        = "/header.php?tab=status";
server[i]     = "Apache";
body[i]       = make_list(
                  '<a href="/print/index.php" target="_top">Print</a>',
                  '<div id="productName">XEROX ColorQube'
                );
i++;


name[i]       = "Identity Services Engine";
url[i]        = "/admin/login.jsp";
dev_type[i]   = "general-purpose";
body[i]       = make_list(
                  '<title>Identity Services Engine</title>',
                  "ciscoLogoImageAlt=",
                  "loginButtonLabel="
                );

i++;

name[i]       = "Lantronix SLC";
dev_type[i]   = "embedded";
url[i]        = "/";
title_re[i]   = make_list(
                  '^Lantronix SLC(8|16|32|48)$'
                );
body_re[i]    = make_list(
                  '<div class=product>SLC(8|16|32|48)</div>'
                );
i++;

name[i]       = "Emerson Liebert IntelliSlot WebCard";
dev_type[i]   = "embedded";
confidence[i] = 80;
url[i]        = "/";
server[i]     = "Allegro-Software-RomPager/";
body[i]       = make_list(
                  '<title>Liebert</title>'
                );
i++;

name[i]       = "Arista EOS";
url[i]        = "/explorer.html";
dev_type[i]   = "switch";
server[i]     = "nginx";
confidence[i] = 99;
title[i]      = make_list(
                  'Command API Explorer'
                );
body[i]       = make_list(
                  'Arista Command API'
                );

i++;

name[i]       = "Virtuozzo";
url[i]        = "/";
server[i]     = "Apache/";
title[i]      = make_list(
                  "Test Page for the Apache HTTP Server"
                );
body[i]       = make_list(
                  "<h1>Virtuozzo Linux <strong>Test Page</strong></h1>",
                  "<p>For information on Virtuozzo products, please visit"
                );
dev_type[i]   = "general-purpose";
confidence[i] = 80;
i++;


n = i;

# Check each web server.
foreach port (ports)
{
  if (!get_port_state(port)) continue;

  prev_url = NULL;
  prev_res = NULL;

  for (i=0; i<n; i++)
  {
    # Ignore it if it's supposed to run on a specific set of ports
    # and this port isn't in that list.
    if (
      !isnull(port_re[i]) &&
      !ereg(pattern:port_re[i], string:string(port))
    ) continue;

    # Examine the Server response header.
    banner = get_http_banner(port:port);
    if (isnull(banner)) cur_server = "";
    else cur_server = egrep(pattern:"^Server:", string:banner);

    if (strlen(cur_server) == 0)
    {
      if (strlen(server[i]) > 0 || strlen(server_re[i]) > 0) continue;
    }
    else
    {
      if (!isnull(server[i]) && server[i] == "") continue;
      if (strlen(server[i]) > 0 && server[i] >!< cur_server) continue;
      if (
        strlen(server_re[i]) > 0 &&
        !ereg(pattern:"^Server: *"+server_re[i]+'[\r\n]*$', string:cur_server)
      ) continue;
    }

    # Fetch the URL if we should test for something in it.
    if (
      isnull(url[i]) &&
      (
        !isnull(title[i]) || !isnull(title_re[i]) ||
        !isnull(body[i]) || !isnull(body_re[i])
      )
    )
    {
      url[i] = "/";
    }
    if (isnull(url[i])) continue;

    if (!isnull(prev_url) && url[i] == prev_url && !isnull(prev_res)) res = prev_res;
    else if (url[i] == '/' && empty_or_null(redir[i]))
    {
      res[0] = res[1] = res[2] = '';
      cached_res = http_get_cache(port:port, item:"/");
      lines = split(cached_res);
      res[0] = lines[0];
      for (j=1; j<max_index(lines); j++)
      {
        if (lines[j] == '\r\n' || lines[j] == '\n') break;
        res[1] += lines[j];
      }
      j++;
      while (j<max_index(lines))
      {
        res[2] += lines[j];
        j++;
      }
    }
    else if (get_kb_item('Services/www/'+port+'/broken'))
    {
      res[2] = '';
    }
    else
    {
      if(empty_or_null(redir[i])) redir[i] = 0;
      res = http_send_recv3(item:url[i], method:"GET", port:port, follow_redirect:redir[i]);

      if (isnull(res)) continue;
      if (isnull(res[2])) res[2] = "";

      prev_url = url[i];
      prev_res = res;
    }

    # Flag when we can move on to the next signature.
    stop_checking = FALSE;

    # Check the headers if appropriate.
    if (!isnull(headers[i]) || !isnull(headers_re[i]))
    {
      cur_headers = res[0] + res[1];
      if (!isnull(headers[i]))
      {
        foreach h (headers[i])
        {
          if (h >!< cur_headers)
          {
            stop_checking = TRUE;
            break;
          }
        }
        if (stop_checking) continue;
      }
      if (!isnull(headers_re[i]))
      {
        foreach h (headers_re[i])
        {
          if (!egrep(pattern:h, string:cur_headers))
          {
            stop_checking = TRUE;
            break;
          }
        }
        if (stop_checking) continue;
      }
    }

    # Check the title if appropriate.
    if (!isnull(title[i]) || !isnull(title_re[i]))
    {
      # Isolate the title.
      cur_title = "";
      title_start = stridx(tolower(res[2]), "<title>");
      if (title_start < 0) continue;
      cur_title = substr(res[2], title_start+strlen("<title>"));

      title_end = stridx(tolower(cur_title), "</title>");
      if (title_end < 0) continue;
      cur_title = substr(cur_title, 0, title_end - 1);

      if (!isnull(title[i]))
      {
        foreach t (title[i])
        {
          if (t >!< cur_title)
          {
            stop_checking = TRUE;
            break;
          }
        }
        if (stop_checking) continue;
      }
      if (!isnull(title_re[i]))
      {
        foreach t (title_re[i])
        {
          if (!egrep(pattern:t, string:cur_title))
          {
            stop_checking = TRUE;
            break;
          }
        }
        if (stop_checking) continue;
      }
    }

    # Check the body if appropriate.
    if (!isnull(body[i]) || !isnull(body_re[i]))
    {
      cur_body = res[2];

      if (!isnull(body[i]))
      {
        foreach b (body[i])
        {
          if (b >!< cur_body)
          {
            stop_checking = TRUE;
            break;
          }
        }
        if (stop_checking) continue;
      }
      if (!isnull(body_re[i]))
      {
        foreach b (body_re[i])
        {
          if (!egrep(pattern:b, string:cur_body))
          {
            stop_checking = TRUE;
            break;
          }
        }
        if (stop_checking) continue;
      }
    }

    # If we get here, we found it.
    if (confidence[i]) confidence = confidence[i];
    else confidence = default_confidence;

    if (dev_type[i]) dev_type = dev_type[i];
    else dev_type = default_dev_type;

    set_kb_item(name:"Host/OS/HTML", value:name[i]);
    set_kb_item(name:"Host/OS/HTML/Confidence", value:confidence);
    set_kb_item(name:"Host/OS/HTML/Type", value:dev_type);

    # Let's make sure the web server is marked as embedded while we're at it.
    replace_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);

    exit(0);
  }
}
