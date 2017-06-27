#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10526);
  script_version ("$Revision: 1.22 $");
  script_cve_id("CVE-2000-0951");
  script_bugtraq_id(1756);
  script_osvdb_id(425);

  script_name(english:"Microsoft IIS WebDAV SEARCH Method Arbitrary Directory Forced Listing");
	script_summary(english:"Checks the presence of the Index Server service");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to inforamtion disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:"It is possible to retrieve the listing of the remote
directories accessible via HTTP, rather than their index.html,
using the Index Server service which provides WebDav capabilities
to this server.

This problem allows an attacker to gain more knowledge
about the remote host, and may make him aware of hidden
HTML files."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Disable the Index Server service."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(
    attribute:'see_also',
    value:'http://support.microsoft.com/kb/272079'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/10/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/04");
 script_cvs_date("$Date: 2016/11/29 20:13:37 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
	script_family(english:"Web Servers");
	script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
	script_require_ports("Services/www", 80);
	exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

if (! get_port_state(port)) exit(0);

data = 
'<?xml version="1.0"?>\r\n' +
'<g:searchrequest xmlns:g="DAV:">\r\n' +
'<g:sql>\r_n' +
'Select "DAV:displayname" from scope()\r\n' +
'</g:sql>\r\n' +
'</g:searchrequest>\r\n';

w = http_send_recv3(method:"SEARCH", item:"/", port: port, version: 11,
  content_type: "text/xml", data: data);
if (isnull(w)) exit(0);

if ("HTTP/1.1 207 " >< w[0])
{
  r = strcat(w[1], '\r\n', w[2]);
  if(("DAV:" >< r) && ((".asp" >< r)||(".inc" >< r)))security_warning(port);
}
