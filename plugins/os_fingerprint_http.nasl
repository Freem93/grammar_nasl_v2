#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25247);
  script_version("$Revision: 1.186 $");
  script_cvs_date("$Date: 2017/03/13 21:17:23 $");

  script_name(english:"OS Identification : HTTP");
  script_summary(english:"Determines the remote operating system.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to identify the remote operating system based on the
response from the remote HTTP server.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to identify the remote operating system type and
version by examining the data returned by the remote HTTP server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("distro_guess.nasl", "find_service1.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

#
# The Linux distributions are taken care of via distro_guess.nasl
#
os_list = get_kb_item("Host/Linux/Distribution");
if (!isnull(os_list))
{
  confidence = 95;
  os_str = "";

  foreach os (split(os_list, keep:FALSE))
  {
    os -= " - ";

    if ( "Ubuntu 11.10" >< os)
    os = "Linux Kernel 3.0 on " + os;
    else if ("Ubuntu 12.04" >< os)
    os = "Linux Kernel 3.0 on " + os;
    else if ("Ubuntu 12.10" >< os)
    os = "Linux Kernel 3.5 on " + os;
    else if ("Ubuntu 13.04" >< os)
    os = "Linux Kernel 3.8 on " + os;
    else if ("Ubuntu 13.10" >< os)
    os = "Linux Kernel 3.11 on " + os;
    else if ("Ubuntu 14.04" >< os)
    os = "Linux Kernel 3.13 on " + os;
    else if ("Ubuntu 14.10" >< os)
    os = "Linux Kernel 3.16 on " + os;
    else if ("Ubuntu 15.04" >< os)
    os = "Linux Kernel 3.19 on " + os;
    else if ("Ubuntu 15.10" >< os)
    os = "Linux Kernel 4.2 on " + os;
    else if ("Ubuntu 16.04" >< os)
    os = "Linux Kernel 4.4 on " + os;
    else if ( "Ubuntu" >< os )
    os = "Linux Kernel 2.6 on " + os;
    else if ( "Debian 8.0 (jessie)" >< os )
    os = "Linux Kernel 3.16 on " + os;
    else if ( "Debian 7.0 (wheezy)" >< os )
    os = "Linux Kernel 3.2 on Debian 7.0 (wheezy)";
    else if ( "Debian 6.0 (squeeze)" >< os )
    os = "Linux Kernel 2.6 on Debian 6.0 (squeeze)";
    else if ( "Debian 5.0 (lenny)" >< os )
    os = "Linux Kernel 2.6 on Debian 5.0 (lenny)";
    else if ( "Debian 4.0 (etch)" >< os )
    os = "Linux Kernel 2.6 on Debian 4.0 (etch)";
    else if ( "Debian 3.1 (sarge)" >< os )
    os = "Linux Kernel 2.4 on Debian 3.1 (sarge)";
    else if ( "Debian 3.0 (woody)" >< os )
    os = "Linux Kernel 2.2 on Debian 3.0 (woody)";
    else if ( "Debian 2.2 (potato)" >< os )
    os = "Linux Kernel 2.2 on Debian 2.2 (potato)";
    else if ( "Debian 2.1 (slink)" >< os )
    os = "Linux Kernel 2.0 on Debian 2.2 (potato)";
    else if ( "Debian 2.0 (hamm)" >< os )
    os = "Linux Kernel 2.0 on Debian 2.2 (potato)";
    else if ( "Debian 1.3 (bo)" >< os )
    os = "Linux Kernel 2.0 on Debian 1.3 (bo)";
    else if ( "Debian 1.2 (rex)" >< os )
    os = "Linux Kernel 2.0 on Debian 1.2 (rex)";
    else if ( "Debian 1.1 (buzz)" >< os )
    os = "Linux Kernel 2.0 on Debian 1.1 (buzz)";
    else if ( "Fedora 25" >< os )
    os = "Linux Kernel 4.8 on Fedora release 25";
    else if ( "Fedora 24" >< os )
    os = "Linux Kernel 4.6 on Fedora release 24";
    else if ( "Fedora 23" >< os )
    os = "Linux Kernel 4.2 on Fedora release 23";
    else if ( "Fedora 22" >< os )
    os = "Linux Kernel 4.0 on Fedora release 22";
    else if ( "Fedora 21" >< os )
    os = "Linux Kernel 3.17 on Fedora release 21";
    else if ( "Fedora 20" >< os )
    os = "Linux Kernel 3.12 on Fedora release 20";
    else if ( "Fedora 19" >< os )
    os = "Linux Kernel 3.9 on Fedora release 19";
    else if ( "Fedora 18" >< os )
    os = "Linux Kernel 3.7 on Fedora release 18";
    else if ( "Fedora 17" >< os )
    os = "Linux Kernel 3.3 on Fedora release 17";
    else if ( "Fedora 16" >< os )
    os = "Linux Kernel 3.0 on Fedora release 16";
    else if ( "Fedora 15" >< os )
    os = "Linux Kernel 2.6 on Fedora release 15";
    else if ( "Fedora 14" >< os )
    os = "Linux Kernel 2.6 on Fedora release 14";
    else if ( "Fedora 13" >< os )
    os = "Linux Kernel 2.6 on Fedora release 13";
    else if ( "Fedora 12" >< os )
    os = "Linux Kernel 2.6 on Fedora release 12";
    else if ( "Fedora 11" >< os )
    os = "Linux Kernel 2.6 on Fedora release 11";
    else if ( "Fedora 10" >< os )
    os = "Linux Kernel 2.6 on Fedora release 10";
    else if ( "Fedora 9" >< os )
    os = "Linux Kernel 2.6 on Fedora release 9";
    else if ( "Fedora 8" >< os )
    os = "Linux Kernel 2.6 on Fedora release 8";
    else if ( "Fedora 7" >< os )
    os = "Linux Kernel 2.6 on Fedora release 7";
    else if ( "Fedora Core 6" >< os )
    os = "Linux Kernel 2.6 on Fedora Core release 6";
    else if ( "Fedora Core 5" >< os )
    os = "Linux Kernel 2.6 on Fedora Core release 5";
    else if ( "Fedora Core 4" >< os )
    os = "Linux Kernel 2.6 on Fedora Core release 4";
    else if ( "Fedora Core 3" >< os )
    os = "Linux Kernel 2.6 on Fedora Core release 3";
    else if ( "Fedora Core 2" >< os )
    os = "Linux Kernel 2.6 on Fedora Core release 2";
    else if ( "Fedora Core 1" >< os )
    os = "Linux Kernel 2.4 on Fedora Core release 1";
    else if ("openSUSE Linux 42.1" >< os)
    os = "Linux Kernel 4.1 on openSUSE 42.1";
    else if ("openSUSE Linux 13.2" >< os)
    os = "Linux Kernel 3.16 on openSUSE 13.2";
    else if ("openSUSE Linux 13.1" >< os)
      os = "Linux Kernel 3.11 on openSUSE 13.1";
    else if ("openSUSE Linux 12.3" >< os)
      os = "Linux Kernel 3.7 on openSUSE 12.3";
    else if ("openSUSE Linux 12.2" >< os)
          os = "Linux Kernel 3.4 on openSUSE 12.2";
    else if ("openSUSE Linux 12.1" >< os)
          os = "Linux Kernel 3.1 on openSUSE 12.1";
    else if ("openSUSE Linux 11.4" >< os)
          os = "Linux Kernel 2.6 on openSUSE 11.4";
    else if ( "SuSE Linux 12.0" >< os )
    os = "Linux Kernel 3.12 on SuSE Linux 12.0";
    else if ( "SuSE Linux 11.0" >< os )
    os = "Linux Kernel 2.6 on SuSE Linux 11.0";
    else if ( "SuSE Linux 10.4" >< os )
    os = "Linux Kernel 2.6 on SuSE Linux 10.4";
    else if ( "SuSE Linux 10.3" >< os )
    os = "Linux Kernel 2.6 on SuSE Linux 10.3";
    else if ( "SuSE Linux 10.2" >< os )
    os = "Linux Kernel 2.6 on SuSE Linux 10.2";
    else if ( "SuSE Linux 10.1" >< os )
    os = "Linux Kernel 2.6 on SuSE Linux 10.1";
    else if ( "SuSE Linux 10.0" >< os )
    os = "Linux Kernel 2.6 on SuSE Linux 10.0";
    else if ( "SuSE Linux 9.3" >< os )
    os = "Linux Kernel 2.6 on SuSE Linux 9.3";
    else if ( "SuSE Linux 9.2" >< os )
    os = "Linux Kernel 2.6 on SuSE Linux 9.2";
    else if ( "SuSE Linux 9.1" >< os )
    os = "Linux Kernel 2.6 on SuSE Linux 9.1";
    else if ( "SuSE Linux 9.0" >< os )
    os = "Linux Kernel 2.4 on SuSE Linux 9.0";
    else if ( "SuSE Linux 8.2" >< os )
    os = "Linux Kernel 2.4 on SuSE Linux 8.2";
    else if ( "SuSE Linux 8.0" >< os )
    os = "Linux Kernel 2.4 on SuSE Linux 8.0";
    else if ( "SuSE Linux 7.3" >< os )
    os = "Linux Kernel 2.4 on SuSE Linux 7.3";
    else if ( "SuSE Linux 7.2" >< os )
    os = "Linux Kernel 2.4 on SuSE Linux 7.2";
    else if ( "SuSE Linux 7.1" >< os )
    os = "Linux Kernel 2.2 on SuSE Linux 7.1";
    else if ( "SuSE Linux 6.4" >< os )
    os = "Linux Kernel 2.2 on SuSE Linux 6.4 or 7.0";
    else if ( "SuSE Linux 6.1" >< os )
    os = "Linux Kernel 2.2 on SuSE Linux 6.1";
    else if ( "Red Hat Enterprise Linux 7" >< os )
    os = "Linux Kernel 3.10 on Red Hat Enterprise Linux 7";
    else if ( "Red Hat Enterprise Linux 6" >< os )
    os = "Linux Kernel 2.6 on Red Hat Enterprise Linux 6";
    else if ( "Red Hat Enterprise Linux 5" >< os )
    os = "Linux Kernel 2.6 on Red Hat Enterprise Linux 5";
    else if ( "Red Hat Enterprise Linux 4" >< os )
    os = "Linux Kernel 2.6 on Red Hat Enterprise Linux 4";
    else if ( "Red Hat Enterprise Linux 3" >< os )
    os = "Linux Kernel 2.4 on Red Hat Enterprise Linux 3";
    else if ( "Red Hat Enterprise Linux 2.1" >< os )
    os = "Linux Kernel 2.4 on Red Hat Enterprise Linux 2.1";
    else if (os =~ "^Scientific Linux 7$")
    os = "Linux Kernel 3.10 on " + os;
    else if ( os =~ "^Scientific Linux [456]$" )
    os = "Linux Kernel 2.6 on " + os;
    else if ( os =~ "^Scientific Linux 3$" )
    os = "Linux Kernel 2.4 on " + os;
    else if ( os =~ "^Oracle Linux 7$")
    os = "Linux Kernel 3.8 on " + os;
    else if ( os =~ "^Oracle (Unbreakable Linux 4|Enterprise Linux 5|Linux 6)$" )
    os = "Linux Kernel 2.6 on " + os;
    else if ( "CentOS 7" >< os )
    os = "Linux Kernel 3.10 on CentOS Linux release 7";
    else if ( "CentOS 6" >< os )
     os = "Linux Kernel 2.6 on CentOS Linux release 6";
    else if ( "CentOS 5" >< os )
    os = "Linux Kernel 2.6 on CentOS release 5";
    else if ( "CentOS 4" >< os )
    os = "Linux Kernel 2.6 on CentOS release 4";
    else if ( "CentOS 3" >< os )
    os = "Linux Kernel 2.4 on CentOS release 3";
    else if ( "CentOS 2.1" >< os )
    os = "Linux Kernel 2.4 on CentOS release 2.1";
    else if ( os =~ "Red Hat Linux ([89]|7\.1)"  )
    os = "Linux Kernel 2.4 on " + os;
    else if ( os =~ "Red Hat Linux (7\.0|6\.)" )
    os = "Linux Kernel 2.2 on " + os;
    else if ( os =~ "Red Hat Linux 5" )
    os = "Linux Kernel 2.0 on " + os;
    else if ( "Mandriva Linux 2007" >< os )
    os = "Linux Kernel 2.6 on " + os;
    else if ( "Mandriva Linux 2006" >< os )
    os = "Linux Kernel 2.6 on " + os;
    else if ( "Mandriva Linux 2005" >< os )
    os = "Linux Kernel 2.6 on " + os;
    else if ( "Mandrake Linux 10.1" >< os )
    os = "Linux Kernel 2.6 on " + os;
    else if ( "Mandrake Linux 10.0" >< os )
    os = "Linux Kernel 2.6 on " + os;
    else if ( "Mandrake Linux 9" >< os )
    os = "Linux Kernel 2.4 on " + os;
    else if ( "Mandrake Linux 8" >< os )
    os = "Linux Kernel 2.4 on " + os;
    else if ( "Mandrake Linux 7" >< os )
    os = "Linux Kernel 2.2 on " + os;
    else if ( "Mandriva Linux 2008.0" >< os )
    os = "Linux Kernel 2.6 on " + os;
    else if ( "Mandriva Linux 2010.0" >< os )
    os = "Linux Kernel 2.6 on " + os;
    else if ( "Mandriva Linux 2010.1" >< os )
    os = "Linux Kernel 2.6 on " + os;
    else if ( "Mandriva Linux 2010.2" >< os )
    os = "Linux Kernel 2.6 on " + os;
    else if ( "Mandriva Linux 2011.0" >< os )
    os = "Linux Kernel 2.6 on " + os;
    else if ( "Mandriva Business Server 1" >< os)
    os = "Linux Kernel 3.4 on " + os;
    else if ( "Mageia 4 on " >< os)
    os = "Linux Kernel 3.12 on " + os;
    else if ( "Mageia 3 on " >< os)
    os = "Linux Kernel 3.8 on " + os;
    else if ( "Mageia 2 on " >< os)
    os = "Linux Kernel 3.3 on " + os;
    else if ( "Mageia 1 on " >< os)
    os = "Linux Kernel 2.6 on " + os;
    else if ( "Virtuozzo 7.2" >< os)
    os = "Linux Kernel 3.10 on " + os;
    else if ( "Virtuozzo 7.3" >< os)
    os = "Linux Kernel 3.10 on " + os;
    else confidence -= 20;

    os_str += os + '\n';
  }
  os_str = chomp(os_str);
  if ('\n' >< os_str) confidence -= 10;

  set_kb_item(name:"Host/OS/HTTP", value:os_str);
  set_kb_item(name:"Host/OS/HTTP/Confidence", value:confidence);
  set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
  exit(0);
}

ports = get_kb_list("Services/www");
if ( isnull(ports) ) exit(0);

ports = make_list(ports);
foreach port ( ports )
{
 if ( ! get_port_state(port) ) continue;

 banner = get_http_banner(port:port);
 if ( ! banner )
 {
   v =  get_unknown_banner2(port: port, dontfetch: 1);
   if (! isnull(v) && v[1] == 'get_http') banner = v[0];
 }
 if (! banner) continue;

 svr = egrep(pattern:"^Server", string:banner, icase: TRUE);
 if ( ! svr )
   svr = egrep(pattern:"^[^:]*Server: ", string:banner, icase: TRUE);
 if ( ! svr ) continue;
 svr = chomp(svr);
 replace_kb_item(name:"Host/OS/HTTP/Fingerprint", value:svr);

 if ( "Microsoft-IIS" >< banner )
 {
  if ( "Microsoft-IIS/3.0" >< banner ) os = "Microsoft Windows NT 4.0";
  else if ( "Microsoft-IIS/4.0" >< banner ) os = "Microsoft Windows NT 4.0";
  else if ( "Microsoft-IIS/5.0" >< banner ) os = "Microsoft Windows 2000 Server";
  else if ( "Microsoft-IIS/5.1" >< banner ) os = "Microsoft Windows XP";
  else if ( "Microsoft-IIS/6.0" >< banner ) os = "Microsoft Windows Server 2003";
  else if ( "Microsoft-IIS/7.0" >< banner ) os = "Microsoft Windows Server 2008";
  else if ( "Microsoft-IIS/7.5" >< banner ) os = "Microsoft Windows Server 2008 R2";
  else if ( "Microsoft-IIS/8.0" >< banner ) os = "Microsoft Windows Server 2012";
  else if ( "Microsoft-IIS/8.5" >< banner ) os = "Microsoft Windows Server 2012 R2";
  else if ( "Microsoft-IIS/10.0" >< banner ) os = "Microsoft Windows 10";

  if ( os )
  {
   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:75);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
  }
 }
 else if ( "Microsoft-HTTPAPI" >< banner )
 {
  if ( "Microsoft-HTTPAPI/1.0" >< banner ) os = 'Microsoft Windows XP\nMicrosoft Server Windows 2003';
  else if ( "Microsoft-HTTPAPI/2.0" >< banner ) os = 'Microsoft Windows Server 2003\nMicrosoft Windows Vista\nMicrosoft Windows Server 2008\nMicrosoft Windows 7\nMicrosoft Windows Server 2008 R2';

  if ( os )
  {
   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:70);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
  }
 }
 else if ( egrep(pattern:"^Server: (IBM_HTTP_Server.*)?Apache.*Win32",string:banner) )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Microsoft Windows");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:5);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 # nb: both IOS and IOS XE have "Server: cisco-IOS".
 else if ( egrep(pattern:"^Server: cisco-IOS",string:banner) )
 {
   if ( egrep(pattern:"^Server: cisco-IOS/[0-9.]+", string:banner) )
   {
     version = ereg_replace(string:chomp(egrep(pattern:"^Server: cisco-IOS/[0-9]+\.[0-9]+ ", string:banner)), pattern:"^Server: cisco-IOS/([0-9.]+).*", replace:"\1");
     if ( version =~ "^[0-9.]+" )
{
     set_kb_item(name:"Host/OS/HTTP", value:'CISCO IOS '+version + '\n' + 'Cisco IOS XE '+version);
    set_kb_item(name:"Host/OS/HTTP/Confidence", value:85);
    set_kb_item(name:"Host/OS/HTTP/Type", value:"router");
 exit(0);
}
   }
   set_kb_item(name:"Host/OS/HTTP", value:'CISCO IOS\nCisco IOS XE');
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:68);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"router");
   exit(0);
 }
 else if ( egrep(pattern:"^Server: 3Com/v",string:banner) )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"3Com Switch");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:71);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"switch");
   exit(0);
 }
 else if ( egrep(pattern:"^Server: (NetApp|Data ONTAP)/", string:banner) )
 {
   # nb: there may be 2 slashes before the version!!!
   v = eregmatch(string: svr, pattern: "^Server: *(NetApp|Data ONTAP)//?([0-9.]+)");
   if (! isnull(v))
   {
     set_kb_item(name:"Host/OS/HTTP", value:"NetApp Release "+v[2]);
     set_kb_item(name:"Host/OS/HTTP/Confidence", value: 95);
     set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   }
   else
   {
     set_kb_item(name:"Host/OS/HTTP", value:"NetApp");
     set_kb_item(name:"Host/OS/HTTP/Confidence", value:81);
     set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   }
   exit(0);
 }
 else if ( egrep(pattern:"^Server: Bull-SMW/", string:banner) )
 {
    set_kb_item(name:"Host/OS/HTTP", value:"AIX");
    set_kb_item(name:"Host/OS/HTTP/Confidence", value:10);
    set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
    exit(0);
 }
 else if ( '\r\nWWW-Authenticate: Basic realm="Linksys WAP54G"\r\n' >< banner &&
         '\r\nServer: httpd\r\n' >< banner )
 {
    set_kb_item(name:"Host/OS/HTTP", value:"Linksys WAP54G");
    set_kb_item(name:"Host/OS/HTTP/Confidence", value:99);
    set_kb_item(name:"Host/OS/HTTP/Type", value:"wireless-access-point");
    exit(0);
 }
 else if ('WWW-Authenticate: Basic realm="APC Management Card"' >< banner &&
         egrep(pattern:"^Server: Allegro-Software-RomPager/", string:banner))
 {
    set_kb_item(name:"Host/OS/HTTP", value:"APC UPS Management Card");
    set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
    set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
    exit(0);
 }
 else if ( egrep(pattern:"^Server: HPSMH", string:banner) )
 {
    set_kb_item(name:"Host/OS/HTTP", value:"HP-UX");
    set_kb_item(name:"Host/OS/HTTP/Confidence", value:10);
    set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
    exit(0);
 }
 else if ( egrep(pattern:"^Server: Jetty/.*HP-UX", string:banner) )
 {
   line = egrep(pattern:"^Server: Jetty/.*HP-UX", string:banner);
   line = ereg_replace(pattern:".*\((HP-UX.*)\).*", string:line, replace:"\1");
   line = ereg_replace(pattern:" java/[0-9][0-9.]+", replace:"", string:line);
   set_kb_item(name:"Host/OS/HTTP", value:line);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:100);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( egrep(pattern:"^Server: Apache/.+ HP-UX_Apache-based_Web_Server", string:banner) )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"HP-UX");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: IP-Phone Solution" >< banner &&
   'WWW-Authenticate: Basic realm="WirelessIP5000A"' >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Hitachi WIP5000 IP Phone Terminal");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:100);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if (
   "Server: Web Server" >< banner &&
   egrep(pattern:"Location: https?://[^/]+/webvpn.html", string:banner)
 )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"CISCO VPN Concentrator");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:100);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ('WWW-Authenticate: Basic realm="Please enter your user name and password on DSL-502T"' >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"D-Link DSL-502T Modem/Router");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:100);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"router");
   exit(0);
 }
 else if (
   "Server: Linux" >< banner &&
   ereg(pattern:", (DIR-6[1245]5(.+)?|DSL-2890AL)", string:banner)
 )
 {
   os = "D-Link Wireless Access Point";
   match = eregmatch(pattern:", (DIR-6[1245]5(.+)?|DSL-2890AL)", string:banner);
   if (!isnull(match))
   {
     os += " - " + match[1];

     match = eregmatch(pattern:" Ver (([A-Z]+_)?[0-9][0-9.]+)$", string:banner);
     if (!isnull(match)) os += ' with firmware version ' + match[1];
   }

   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:100);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"wireless-access-point");
   exit(0);
 }
 else if ( "Server: Apache/2.2.14 (FreeBSD)" >< banner  )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 7.3");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if (
   "Server: Apache/2.4.16 (FreeBSD)" >< banner
   ||
   "Server: Apache/2.4.23 (FreeBSD)" >< banner
 )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 10.3");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: Apache/2.2.17 (FreeBSD)" >< banner  )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 7.4\nFreeBSD 8.2");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:85);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: Apache/2.2.13 (FreeBSD)" >< banner  )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 8.0");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: Apache/2.2.15 (FreeBSD)" >< banner  )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 8.1");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: Apache/2.2.22 (FreeBSD)" >< banner  )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 8.3");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: Apache/2.2.21 (FreeBSD)" >< banner  )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 9.0");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: Apache/2.2.23 (FreeBSD)" >< banner  )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 9.1");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: Apache/2.2.24 (FreeBSD)" >< banner  )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 8.4");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ("Server: Apache/2.2.25 (FreeBSD)" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 9.2");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ("Server: Apache/2.4.10 (FreeBSD)" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 10.1");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ("Server: Apache/2.4.9 (FreeBSD)" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 9.3");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ("Server: Apache/2.4.6 (FreeBSD)" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"FreeBSD 10.0");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: Apache/1.3.33 (Darwin)" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:'Mac OS X 10.3\nMac OS X 10.4');
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:85);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: Apache/1.3.41 (Darwin)" >< banner  )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Mac OS X 10.4");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( "Server: Cisco AWARE 2.0" >< banner &&
           egrep(pattern: "^Set-Cookie: +webvpn[a-z]*=", string: banner) )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"CISCO ASA 5500");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if (egrep(pattern: "^Server: Apache/[12].* \(OpenVMS\)", string: banner))
 {
   set_kb_item(name:"Host/OS/HTTP", value:"OpenVMS");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 76);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if ( egrep(pattern:"^Server: Jetty/.*SunOS/", string:banner) )
 {
  line =  egrep(pattern:"^Server: Jetty/.*SunOS/", string:banner);

  os = "Solaris";
  match = eregmatch(pattern:"^Server: Jetty/.*SunOS/5\.([0-9]+) (sparc|x86)", string:banner);
  if (!isnull(match))
  {
    version = match[1];
    if (int(version) >= 7) os += " " + version;
    else os += " 2." + version;

    os += " (" + match[2] + ")";
  }
  set_kb_item(name:"Host/OS/HTTP", value:os);
  set_kb_item(name:"Host/OS/HTTP/Confidence", value:70);
  set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
  exit(0);
 }
 else if (egrep(pattern:"^Server: Jetty/.*\(Windows ", string:banner))
 {
  line =  egrep(pattern:"^Server: Jetty/.*\(Windows ", string:banner);

  os = "Microsoft Windows";
  confidence = 61;

  match = eregmatch(pattern:"^Server: Jetty/.*\((Windows( Server)? [^/]+)[/ ][0-9]+\.[0-9]+ ", string:line);
  if (!isnull(match))
  {
    os = "Microsoft " + match[1];
    confidence = 81;
  }
  set_kb_item(name:"Host/OS/HTTP", value:os);
  set_kb_item(name:"Host/OS/HTTP/Confidence", value:confidence);
  set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
  exit(0);
 }
 else if ("Server: NetPort Software" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Polycom Teleconferencing Device");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 69);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ("Server: Viavideo-Web" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Polycom Teleconferencing Device");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 69);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "Server: SonicWALL SSL-VPN Web Server" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"SonicWALL SSL-VPN Appliance");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if (egrep(pattern:"^Server: SonicWALL\s*$", string:banner))
 {
   set_kb_item(name:"Host/OS/HTTP", value:"SonicWALL");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if (egrep(pattern:"Server: glass/1\.0 Python/[0-9.]+-IronPort", string:banner))
 {
   set_kb_item(name:"Host/OS/HTTP", value:"AsyncOS");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "Server: BarracudaHTTP" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Barracuda Spam and Virus Firewall\nBarracuda Spam Filter\nBarracuda SSL VPN");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "RIPT-Server: iTunesLib/3." >< banner ) # "Grey" Apple TV
 {
   set_kb_item(name:"Host/OS/HTTP", value:"AppleTV (1st Generation)");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 95);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if (                                         # "Black" Apple TV
  egrep(pattern:"^DAAP-Server: iTunes/[0-9][0-9.]+[a-z][0-9]+ \((Mac )?OS X\)", string:banner)
 )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"AppleTV (2nd or 3rd Generation)");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "Server: Muratec Server Ver" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Muratec Printer");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 95);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"printer");
   exit(0);
 }
 else if ( "Server: Apple Embedded Web Server" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Xserver RAID");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 95);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "Server: Ubicom/" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"ipOS");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 95);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ("Server: Mikrotik HttpProxy" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"MikroTik RouterOS");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"router");
   exit(0);
 }
 else if ( "Server: BlueCoat-Security-Appliance" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Blue Coat Appliance");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 80);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "Server: ePower by Cyber Switching" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Cyber Switching ePower PDU");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "Server: Shadow-OS-390-Web-Server/" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"IBM OS/390");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if (
   "Server: XOS " >< banner &&
   egrep(pattern:"Server: XOS [0-3][0-9](jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)(19[0-9][0-9]|2[0-9]+) ", string:banner)
 )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"ExtremeXOS Network Operating System");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "Server: TRMB/" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Trimble");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( "Server: Polycom SoundPoint IP Telephone HTTPd" >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Polycom SoundPoint IP Phone");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ( egrep(pattern:"^Server: CERN httpd .+\(VAX VMS\)", string:banner) )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"VAX/VMS");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"general-purpose");
   exit(0);
 }
 else if (egrep(pattern:"^Server: *Linux/[0-9]+\.[0-9.]+-I9100XWK[A-Z0-9]+-CL[0-9]+ DoaHTTP", string: banner))
 {
   # Server: Linux/2.6.35.7-I9100XWKJ2-CL676699 DoaHTTP
   # Model GT-I9100 (Samsung Galaxy S2)
   # Baseband I91000XXKI4
   # Kernel Linux/2.6.35.7-I9100XWKJ2-CL676699 root@DELLL144 #2
   # Android version 2.3.5
   # Version GINGERBREAD.XWJ2
   #
   # Previous version:
   # Server: Linux/2.6.35.7-I9100XWKI4-CL575468 DoaHTTP
   v = eregmatch(string: svr, pattern: "^Server: *Linux/([0-9]+\.[0-9.]+)-I9100(XWK[A-Z0-9]+)-CL([0-9]+) DoaHTTP");
   if (! isnull(v))
   {
     if (v[2] == 'XWKJ2') a = "Android 2.3.5";
     else if (v[2] == 'XWKI4') a = "Android 2.3.4";
     else a = "Android";
     set_kb_item(name:"Host/OS/HTTP", value:
"Linux Kernel " + v[1] + " on " + a + " (Samsung Galaxy S2)");
     set_kb_item(name:"Host/OS/HTTP/Confidence", value:95);
     set_kb_item(name:"Host/OS/HTTP/Type", value:"mobile");
     exit(0);
   }
 }
 else if (egrep(pattern: "^SERVER: *Linux/2.6.29-omap1, UPnP/1.0, Portable SDK for UPnP devices/1.6.6", string: banner))
 {
   # Archos 70
   set_kb_item(name:"Host/OS/HTTP", value:"Linux Kernel 2.6.29 on Android 2.2.1");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"mobile");
   exit(0);
 }
 else if ("Server: Netwave IP Camera" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Foscam IP Camera");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:85);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"camera");
   exit(0);
 }
 else if ("Server: RUGGEDCOM/" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Rugged Operating System");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:85);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ("Server: Snap Appliance, Inc." >< banner)
 {
   os = "GuardianOS";
   if (egrep(pattern:"^Server: Snap Appliance, Inc\./[0-9.]+", string:banner))
   {
     version = ereg_replace(string:chomp(egrep(pattern:"^Server: Snap Appliance, Inc\./[0-9]+\.", string:banner)), pattern:"^Server: Snap Appliance, Inc\./([0-9.]+).*", replace:"\1");
     if (version =~ "^[0-9.]+") os += " " + version;
   }
   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:85);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ("Server: Oracle-ILOM-Web-Server/" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Oracle Integrated Lights Out Manager");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:95);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if (
  egrep(pattern:"^Server: M1 WebServer/[0-9.]+-VxWorks", string:banner) ||
  egrep(pattern:"^Server: WindRiver-WebServer/", string:banner)
 )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"VxWorks");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:60);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ("Server: KM-MFP-http/" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Konica Printer");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value: 90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"printer");
   exit(0);
 }
 else if ("SERVER: VxWorks" >< banner)
 {
   os = "VxWorks";
   match = eregmatch(pattern:"^SERVER: VxWorks/?([0-9][0-9.]+) UPnP", string:banner);
   if (!isnull(match)) os += " " + match[1];

   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:60);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if (
  "Server: Z-World Rabbit" >< banner &&
  '\r\nWWW-Authenticate: Basic realm="Net Optics Bypass Switch"' >< banner
 )
 {
   os = "Net Optics Bypass Switch";

   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:90);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"switch");
   exit(0);
 }
 else if ("Server: TopLayer/AM-IPS" >< banner)
 {
   os = "Corero TopLayer IPS";

   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:80);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ("Server: PanWeb Server/ -" >< banner)
 {
   os = "Palo Alto Networks PAN-OS";

   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:80);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"firewall");
   exit(0);
 }

 else if ("Server: ADTRAN, Inc." >< banner)
 {
   os = "ADTRAN Operating System";

   type = "embedded";
   if ('Basic realm="NetVanta ' >< banner) type = 'router';

   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:78);
   set_kb_item(name:"Host/OS/HTTP/Type", value:type);
   exit(0);
 }
 else if (
   'Server: GoAhead-Webs' >< banner &&
   (
     'Basic realm="NISUTA NS-WIR' >< banner ||
     'Basic realm="NISUTA NS-WMR' >< banner
   )
 )
 {
   os = 'NISUTA';

   match = eregmatch(pattern:'NISUTA (NS-W[IM]R[0-9][^"]+)', string:banner);
   if (!isnull(match)) os += ' ' + match[1];

   os += ' Wireless Access Point';

   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:80);
   set_kb_item(name:"Host/OS/HTTP/Type", value:'wireless-access-point');
   exit(0);
 }
 else if (
   "Server: mwg-ui" >< banner &&
   egrep(pattern:'Location: http.+/Konfigurator/request', string:banner)
 )
 {
   os = "McAfee Web Gateway";
   type = "embedded";

   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:75);
   set_kb_item(name:"Host/OS/HTTP/Type", value:type);
   exit(0);
 }
 else if (
   "Server: eHTTP v" >< banner &&
   egrep(pattern:'WWW-Authenticate: Basic realm="ProCurve J[0-9][0-9A-Z]+"', string:banner)
 )
 {
   os = "HP Switch";
   type = "switch";

   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:75);
   set_kb_item(name:"Host/OS/HTTP/Type", value:type);
   exit(0);
 }
 else if ("Server: VBrick VB6000 Server" >< banner)
 {
   os = "VBrick";
   type = "embedded";

   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:70);
   set_kb_item(name:"Host/OS/HTTP/Type", value:type);
   exit(0);
 }
 else if ("Server: A10WS/" >< banner)
 {
   os = "A10 Networks Advanced Core OS";
   type = "load-balancer";

   set_kb_item(name:"Host/OS/HTTP", value:os);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:70);
   set_kb_item(name:"Host/OS/HTTP/Type", value:type);
   exit(0);
 }
 else if (
   "Server: UPS_Server/" >< banner &&
   "WWW-Authenticate" >< banner
 )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"ConnectUPS Web/SNMP Card");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:60);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if (
  'WWW-Authenticate: Digest realm="ClickShare"' >< banner
 )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Barco ClickShare");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:75);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }

 slash = http_get_cache(port: port, item: '/');
 if (!slash) slash = banner;

 if (
   '<title>EMC Celerra Network Server</title>' >< slash &&
   '<script>window.location.pathname=\'/Login\';</script>' >< slash &&
   egrep(string: slash, pattern: '>Copyright \\(c\\) 20[0-9][0-9] EMC Corporation Unpublished - All Rights Reserved<')
 )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Linux Kernel 2.6 on an EMC Celerra Network Server");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:70);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if (
   'Server: UPS_Server/' >< slash &&
   '<TITLE>ConnectUPS Web/SNMP Card' >< slash &&
   'var nTitle = "?upsIDInformation";' >< slash
 )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"ConnectUPS Web/SNMP Card");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:70);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if (
   'Server: Apache' >< slash &&
   '<TITLE>Xceedium Xsuite' >< slash
 )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Xceedium Xsuite Appliance");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:70);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ("Server: LANTIME" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Meinberg LANTIME");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:95);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"scada");
   exit(0);
 }
 else if (
   "Server: HP HTTP Server" >< banner &&
   "HP Officejet" >< banner
 )
 {
   match = eregmatch(string:banner, pattern:"(HP Office[jJ]et (Pro )?([0-9]+))");
   if (!isnull(match)) value = match[1];
   else value = "HP Officejet";

   set_kb_item(name:"Host/OS/HTTP", value:value);
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:100);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ("Server: YAMAHA-RT" >< banner || "Server: Yamaha-RT" >< banner)
 {
   set_kb_item(name:"Host/OS/HTTP", value:"YAMAHA-RT");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:95);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"router");
   exit(0);
 }
 else if ('WWW-Authenticate: Basic realm="Wireless Adapter WA-1100"' >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"WA-1100");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:80);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
 else if ('<title>Awarepoint Bridge' >< banner )
 {
   set_kb_item(name:"Host/OS/HTTP", value:"Awarepoint Bridge");
   set_kb_item(name:"Host/OS/HTTP/Confidence", value:100);
   set_kb_item(name:"Host/OS/HTTP/Type", value:"embedded");
   exit(0);
 }
}
