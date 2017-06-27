#
# (C) Tenable Network Security, Inc.
#

#
# This script does not check for CVE-2002-0371 per se,
# but references it as an example of an abuse in the gopher
# protocol. MS advisory MS02-027 also suggests disabling
# the gopher protocol handling completely.
#

include("compat.inc");

if (description)
{ 
 script_id(11305);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2014/05/09 18:59:10 $");

 script_cve_id("CVE-2002-0371");
 script_bugtraq_id(4930);
 script_osvdb_id(3004);
 
 script_name(english: "HTTP Proxy Open gopher:// Request Relaying");
 script_summary(english:"Determines if we can use the remote web proxy to do gopher requests");
 
 script_set_attribute(attribute:"synopsis", value:
"The HTTP proxy accepts gopher:// requests.");
 script_set_attribute(attribute:"description", value:
"Gopher is an old network protocol which predates HTTP and is nearly 
unused today. As a result, gopher-compatible software is generally 
less audited and more likely to contain security bugs than others.

By making gopher requests, an attacker may evade your firewall settings,
by making connections to port 70, or may even exploit arcane flaws in 
this protocol to gain more privileges on this host (see the attached CVE
id for such an example).");
 script_set_attribute(attribute:"solution", value:
"Reconfigure your proxy so that it refuses gopher requests.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/02");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");

 script_dependencie("find_service1.nasl", "proxy_use.nasl");
 script_require_keys("Proxy/usage");
 script_require_ports("Services/http_proxy", 3128, 8080);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/http_proxy"), port:3128);
ports = add_port_in_list(list:ports, port:8080);

proxy_use = get_kb_item("Proxy/usage");
if (! proxy_use) exit(0);

foreach port (ports)
{
  rq = http_mk_proxy_request(port: 70, method: "GET", scheme: "gopher", host: get_host_name(), item: "/", version: 10);
  r = http_send_recv_req(port: port, req: rq);
  if (! isnull(r) && r[0] =~ "^HTTP/1\.[01] (200|503) ") security_note(port);
}
