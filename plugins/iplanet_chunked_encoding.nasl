#
# (C) Tenable Network Security, Inc.
#

# Tested against iPlanet 4.1SP10 (vulnerable), 6.0SP4 (not vulnerable)
# and 4.0 (not vulnerable)
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#

include("compat.inc");

if (description)
{
 script_id(11068);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2014/05/26 00:33:32 $");

 script_cve_id("CVE-2002-0845");
 script_bugtraq_id(5433);
 script_osvdb_id(5070);

 script_name(english:"iPlanet Chunked Encoding Processing Remote Overflow");
 script_summary(english:"Checks for the behavior of iPlanet");

 script_set_attribute(attribute:"synopsis", value:
"The remote applicaiton server is affected by a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"This host is running the Sun One/iPlanet web server 4.1 or 6.0. This
web server contains an unchecked buffer in the 'Chunked Encoding'
processing routines. By issuing a malformed request to the web server,
a potential intruder can 'POST' extraneous data and cause the web
server process to execute arbitrary code. This allows the potential
intruder to gain access to this host.");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=102890933623192&w=2");
 script_set_attribute(attribute:"solution", value:
"The vendor has released Sun ONE web server 4.1 service pack 11 and 6.0
service pack 4 to fix this issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/07/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/09");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("www/iplanet", "Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, embedded: 0);

 req1 = string(
		"4\r\n",
		"XXXX\r\n",
		"7FFFFFFF\r\n",
		crap(50), "\r\n\r\n");

b = get_http_banner(port: port, exit_on_fail: 1);
   #
   # We need to make sure this is iPlanet, or else we will
   # false postive against Apache.
   #
if(egrep(pattern:"^Server: .*Netscape-Enterprise", string: b))
{
  w = http_send_recv3(method:"POST", item: "/foo.html", port: port,
    add_headers: make_array("Transfer-Encoding", "chunked"),
    exit_on_fail: 0, data: req1);
  # Vulnerable versions wait for the data to arrive,
  # Patched versions will spew an error 411.
  if (isnull(w)) security_hole(port);
}
else
  exit(0, "The web server on port "+port+" is not iPlanet");
