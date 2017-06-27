#
# (C) Tenable Network Security, Inc.
#

# See also: Xeneo_Web_Server_2.2.9.0_DoS.nasl by Bekrar Chaouki
# I wrote this script at the same time. Although both flaws target the same
# web server, I think that we should keep them separated, because it might
# affect other servers.
#
# References:
# From: "Carsten H. Eiram" <che@secunia.com>
# Subject: Secunia Research: Xeneo Web Server URL Encoding Denial of Service
# To: VulnWatch <vulnwatch@vulnwatch.org>, 
#  Full Disclosure <full-disclosure@lists.netsys.com>, 
#  Bugtraq <bugtraq@securityfocus.com>
# Date: 23 Apr 2003 09:49:56 +0200
#
# From: "David Endler" <dendler@idefense.com>
# To: vulnwatch@vulnwatch.org
# Date: Mon, 4 Nov 2002 00:46:47 -0500
# Subject: iDEFENSE Security Advisory 11.04.02b: Denial of Service Vulnerability in Xeneo Web Server
# 


include("compat.inc");

if(description)
{
 script_id(11546);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2002-1248");
 script_bugtraq_id(6098);
 script_osvdb_id(14516);
 
 script_name(english:"Xeneo Web Server %A Request Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server with a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a vulnerable version of the Xeneo web server. 
It is possible to crash the web server by requesting a malformed URL ending 
with /%A or /%." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/11/04");
 script_cvs_date("$Date: 2011/03/14 21:48:16 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Crashes Xeneo web server with /%A or /%");
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

b = get_http_banner(port: port);
if ( "Xeneo/" >!< b ) exit(0);

if(safe_checks())
{
  # I got one banner: "Server: Xeneo/2.2"
  if (b =~ 'Server: *Xeneo/2\\.(([0-1][ \t\r\n.])|(2(\\.[0-9])?[ \t\r\n]))')
  {
    report = "
Note that Nessus did not perform a real test and just checked the
version number in the banner since safe checks are enabled.";
    security_warning(port: port, extra: report);
  }
    
  exit(0);
}

if (http_is_dead(port:port))exit(0);
  
items = make_list("/%A", "/%");

foreach i (items)
{
  r = http_send_recv3(port: port, item: i, method: "GET");
  if (http_is_dead(port:port))
  {
    security_warning(port);
    exit(0);
  }
}
