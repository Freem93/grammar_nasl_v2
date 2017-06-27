#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11695);
 script_version ("$Revision: 1.14 $");
 script_cvs_date("$Date: 2014/07/11 19:38:17 $");
 script_cve_id("CVE-2003-0276");
 script_osvdb_id(11091);
 
 script_name(english:"Pi3Web Malformed GET Request Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a remote overflow." );
 script_set_attribute(attribute:"description", value:
"The remote Pi3Web web server may crash when it is sent 
a malformed request, like :

	GET /</?SortName=A

This issue may allow the execution of arbitrary code." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Pi3Web 2.0.2 beta 2 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/28");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:pi3:pi3web");
 script_end_attributes();

 script_summary(english:"Tests for a DoS in Pi3Web");
 script_category(ACT_MIXED_ATTACK);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_family(english: "Web Servers");
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include ("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "Pi3Web/" >!< banner ) exit(0);

if(safe_checks())
{
 	if(egrep(pattern:"^Server: Pi3Web/2\.0\.([01]|2 *beta *[01])([^0-9]|$)", string:banner))
	{
       		security_warning(port);
		exit(0);
	}
	
}

if (http_is_dead(port:port)) exit(0);
r = http_send_recv3(method: "GET", item:"/</?SortName=A", port:port);
if (http_is_dead(port:port, retry: 3))security_warning(port);


