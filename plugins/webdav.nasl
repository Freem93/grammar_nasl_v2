#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(10505);
  script_version ("$Revision: 1.28 $");
  script_cvs_date("$Date: 2011/03/14 21:48:15 $");

  script_cve_id("CVE-2000-0869");
  script_bugtraq_id(1656);
  script_osvdb_id(404);
  
  script_name(english:"Apache WebDAV Module PROPFIND Arbitrary Directory Listing");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to an information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"The WebDAV module can be used to obtain a listing of the remote web
server directories even if they have a default page such as
index.html. 

This allows an attacker to gain valuable information about the
directory structure of the remote host and could reveal the presence
of files which are not intended to be visible." );
 script_set_attribute(attribute:"solution", value:
"Disable the WebDAV module, or restrict its access to authenticated and
trusted clients." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/09/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/09/07");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks the presence of WebDAV");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

r = http_send_recv3(port: port, item: '/', version: 11, method: 'PROPFIND',
  exit_on_fail: 1,
  add_headers: make_array("Content-Type", "text/xml",
			 "Depth", "1"),
  data : '<?xml version="1.0"?>\r\n<a:propfind xmlns:a="DAV:">\r\n <a:prop>\r\n  <a:displayname:/>\r\n </a:prop>\r\n</a:propfind>\r\n' );

if("HTTP/1.1 207 " >< r[0] && "D:href" >< r[2])
 security_warning(port);
