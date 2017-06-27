#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16060);
 script_version ("$Revision: 1.13 $");
 script_cve_id("CVE-2004-2602", "CVE-2004-2603");
 script_bugtraq_id(12105);
 script_osvdb_id(12597, 12598, 12631);

 script_name(english:"Help Center Live Multiple Remote Vulnerabilities (Cmd Exec, XSS)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Help Center Live, a help desk application
written in PHP. 

The remote version of this software is vulnerable to various flaws,
including one that may allow an attacker to execute arbitrary commands
on the remote host subject to the privileges of the web server user id
provided PHP's 'register_globals' setting is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00058-12242004" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/25");
 script_cvs_date("$Date: 2011/03/14 21:48:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines if Help Center Live can include third-party files");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/inc/pipe.php?HCL_path=http://xxxxxx./");
 r = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if ( "http://xxxxxx./inc/DecodeMessage.inc" >< buf )
 {
  security_warning(port);
  exit(0);
 }
}
